#include "lantern/http/metrics.h"

#include "lantern/http/common.h"
#include "lantern/support/log.h"
#include "lantern/support/strings.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define LANTERN_METRICS_BUFFER_SIZE 4096

static int format_metrics_body(
    const struct lantern_metrics_snapshot *snapshot,
    char **out_body,
    size_t *out_len) {
    if (!snapshot || !out_body || !out_len) {
        return -1;
    }
    char node_label[64];
    if (snapshot->node_id[0] != '\0') {
        snprintf(node_label, sizeof(node_label), "%s", snapshot->node_id);
    } else {
        strncpy(node_label, "lantern", sizeof(node_label));
        node_label[sizeof(node_label) - 1] = '\0';
    }

    char head_hex[2 * LANTERN_ROOT_SIZE + 3];
    char justified_hex[2 * LANTERN_ROOT_SIZE + 3];
    char finalized_hex[2 * LANTERN_ROOT_SIZE + 3];

    if (lantern_bytes_to_hex(snapshot->head_root.bytes, LANTERN_ROOT_SIZE, head_hex, sizeof(head_hex), 1) != 0) {
        head_hex[0] = '\0';
    }
    if (lantern_bytes_to_hex(snapshot->justified.root.bytes, LANTERN_ROOT_SIZE, justified_hex, sizeof(justified_hex), 1) != 0) {
        justified_hex[0] = '\0';
    }
    if (lantern_bytes_to_hex(snapshot->finalized.root.bytes, LANTERN_ROOT_SIZE, finalized_hex, sizeof(finalized_hex), 1) != 0) {
        finalized_hex[0] = '\0';
    }

    size_t needed = (size_t)snprintf(
        NULL,
        0,
        "# HELP lantern_slot_current Current head slot for this node\n"
        "# TYPE lantern_slot_current gauge\n"
        "lantern_slot_current{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_slot_justified Last justified slot observed by fork choice\n"
        "# TYPE lantern_slot_justified gauge\n"
        "lantern_slot_justified{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_slot_finalized Last finalized slot observed by fork choice\n"
        "# TYPE lantern_slot_finalized gauge\n"
        "lantern_slot_finalized{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_forkchoice_head_root Fork choice head root (hex label)\n"
        "# TYPE lantern_forkchoice_head_root gauge\n"
        "lantern_forkchoice_head_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_forkchoice_justified_root Latest justified checkpoint root (hex label)\n"
        "# TYPE lantern_forkchoice_justified_root gauge\n"
        "lantern_forkchoice_justified_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_forkchoice_finalized_root Latest finalized checkpoint root (hex label)\n"
        "# TYPE lantern_forkchoice_finalized_root gauge\n"
        "lantern_forkchoice_finalized_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_peer_known_total Known peers (bootnodes + configured)\n"
        "# TYPE lantern_peer_known_total gauge\n"
        "lantern_peer_known_total{node=\"%s\"} %zu\n"
        "# HELP lantern_peer_connected_total Active libp2p peers currently connected\n"
        "# TYPE lantern_peer_connected_total gauge\n"
        "lantern_peer_connected_total{node=\"%s\"} %zu\n"
        "# HELP lantern_gossip_topics_subscribed Gossip topics with active subscriptions\n"
        "# TYPE lantern_gossip_topics_subscribed gauge\n"
        "lantern_gossip_topics_subscribed{node=\"%s\"} %zu\n"
        "# HELP lantern_gossip_validation_failures_total Gossip payloads rejected by validation\n"
        "# TYPE lantern_gossip_validation_failures_total counter\n"
        "lantern_gossip_validation_failures_total{node=\"%s\"} %zu\n"
        "# HELP lantern_validator_local_total Validators assigned to this process\n"
        "# TYPE lantern_validator_local_total gauge\n"
        "lantern_validator_local_total{node=\"%s\"} %zu\n"
        "# HELP lantern_validator_active_total Validators currently enabled for duties\n"
        "# TYPE lantern_validator_active_total gauge\n"
        "lantern_validator_active_total{node=\"%s\"} %zu\n",
        node_label,
        snapshot->head_slot,
        node_label,
        snapshot->justified.slot,
        node_label,
        snapshot->finalized.slot,
        node_label,
        head_hex[0] ? head_hex : "0x0",
        node_label,
        justified_hex[0] ? justified_hex : "0x0",
        node_label,
        finalized_hex[0] ? finalized_hex : "0x0",
        node_label,
        snapshot->known_peers,
        node_label,
        snapshot->connected_peers,
        node_label,
        snapshot->gossip_topics,
        node_label,
        snapshot->gossip_validation_failures,
        node_label,
        snapshot->validators_total,
        node_label,
        snapshot->validators_active);
    if (needed == 0) {
        return -1;
    }
    char *body = malloc(needed + 1);
    if (!body) {
        return -1;
    }
    int written = snprintf(
        body,
        needed + 1,
        "# HELP lantern_slot_current Current head slot for this node\n"
        "# TYPE lantern_slot_current gauge\n"
        "lantern_slot_current{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_slot_justified Last justified slot observed by fork choice\n"
        "# TYPE lantern_slot_justified gauge\n"
        "lantern_slot_justified{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_slot_finalized Last finalized slot observed by fork choice\n"
        "# TYPE lantern_slot_finalized gauge\n"
        "lantern_slot_finalized{node=\"%s\"} %" PRIu64 "\n"
        "# HELP lantern_forkchoice_head_root Fork choice head root (hex label)\n"
        "# TYPE lantern_forkchoice_head_root gauge\n"
        "lantern_forkchoice_head_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_forkchoice_justified_root Latest justified checkpoint root (hex label)\n"
        "# TYPE lantern_forkchoice_justified_root gauge\n"
        "lantern_forkchoice_justified_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_forkchoice_finalized_root Latest finalized checkpoint root (hex label)\n"
        "# TYPE lantern_forkchoice_finalized_root gauge\n"
        "lantern_forkchoice_finalized_root{node=\"%s\",root=\"%s\"} 1\n"
        "# HELP lantern_peer_known_total Known peers (bootnodes + configured)\n"
        "# TYPE lantern_peer_known_total gauge\n"
        "lantern_peer_known_total{node=\"%s\"} %zu\n"
        "# HELP lantern_peer_connected_total Active libp2p peers currently connected\n"
        "# TYPE lantern_peer_connected_total gauge\n"
        "lantern_peer_connected_total{node=\"%s\"} %zu\n"
        "# HELP lantern_gossip_topics_subscribed Gossip topics with active subscriptions\n"
        "# TYPE lantern_gossip_topics_subscribed gauge\n"
        "lantern_gossip_topics_subscribed{node=\"%s\"} %zu\n"
        "# HELP lantern_gossip_validation_failures_total Gossip payloads rejected by validation\n"
        "# TYPE lantern_gossip_validation_failures_total counter\n"
        "lantern_gossip_validation_failures_total{node=\"%s\"} %zu\n"
        "# HELP lantern_validator_local_total Validators assigned to this process\n"
        "# TYPE lantern_validator_local_total gauge\n"
        "lantern_validator_local_total{node=\"%s\"} %zu\n"
        "# HELP lantern_validator_active_total Validators currently enabled for duties\n"
        "# TYPE lantern_validator_active_total gauge\n"
        "lantern_validator_active_total{node=\"%s\"} %zu\n",
        node_label,
        snapshot->head_slot,
        node_label,
        snapshot->justified.slot,
        node_label,
        snapshot->finalized.slot,
        node_label,
        head_hex[0] ? head_hex : "0x0",
        node_label,
        justified_hex[0] ? justified_hex : "0x0",
        node_label,
        finalized_hex[0] ? finalized_hex : "0x0",
        node_label,
        snapshot->known_peers,
        node_label,
        snapshot->connected_peers,
        node_label,
        snapshot->gossip_topics,
        node_label,
        snapshot->gossip_validation_failures,
        node_label,
        snapshot->validators_total,
        node_label,
        snapshot->validators_active);
    if (written < 0 || (size_t)written > needed) {
        free(body);
        return -1;
    }
    *out_body = body;
    *out_len = (size_t)written;
    return 0;
}

static void handle_metrics_request(
    struct lantern_metrics_server *server,
    int client_fd,
    const struct sockaddr_in *peer_addr) {
    char buffer[LANTERN_METRICS_BUFFER_SIZE];
    ssize_t received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return;
    }
    buffer[received] = '\0';

    char method[8];
    char path[128];
    if (sscanf(buffer, "%7s %127s", method, path) != 2) {
        lantern_http_send_response(
            client_fd,
            400,
            "Bad Request",
            "application/json",
            "{\"error\":\"malformed request\"}",
            strlen("{\"error\":\"malformed request\"}"));
        return;
    }
    char peer_text[INET_ADDRSTRLEN];
    if (peer_addr) {
        if (!inet_ntop(AF_INET, &peer_addr->sin_addr, peer_text, sizeof(peer_text))) {
            strncpy(peer_text, "unknown", sizeof(peer_text));
            peer_text[sizeof(peer_text) - 1] = '\0';
        }
    } else {
        strncpy(peer_text, "unknown", sizeof(peer_text));
        peer_text[sizeof(peer_text) - 1] = '\0';
    }

    if (strcmp(method, "GET") != 0 || strcmp(path, "/metrics") != 0) {
        lantern_http_send_response(
            client_fd,
            404,
            "Not Found",
            "application/json",
            "{\"error\":\"unknown endpoint\"}",
            strlen("{\"error\":\"unknown endpoint\"}"));
        lantern_log_info(
            "metrics",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "%s %s -> 404",
            method,
            path);
        return;
    }

    if (!server->callbacks.snapshot) {
        lantern_http_send_response(
            client_fd,
            503,
            "Service Unavailable",
            "application/json",
            "{\"error\":\"metrics unavailable\"}",
            strlen("{\"error\":\"metrics unavailable\"}"));
        lantern_log_error(
            "metrics",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "metrics callback missing");
        return;
    }

    struct lantern_metrics_snapshot snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    if (server->callbacks.snapshot(server->callbacks.context, &snapshot) != 0) {
        lantern_http_send_response(
            client_fd,
            503,
            "Service Unavailable",
            "application/json",
            "{\"error\":\"metrics unavailable\"}",
            strlen("{\"error\":\"metrics unavailable\"}"));
        lantern_log_error(
            "metrics",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "snapshot failed");
        return;
    }

    char *body = NULL;
    size_t body_len = 0;
    if (format_metrics_body(&snapshot, &body, &body_len) != 0) {
        lantern_http_send_response(
            client_fd,
            500,
            "Internal Server Error",
            "application/json",
            "{\"error\":\"metrics formatting failed\"}",
            strlen("{\"error\":\"metrics formatting failed\"}"));
        lantern_log_error(
            "metrics",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "formatting failed");
        return;
    }

    if (lantern_http_send_response(
            client_fd,
            200,
            "OK",
            "text/plain; version=0.0.4",
            body,
            body_len)
        != 0) {
        lantern_log_error(
            "metrics",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "send failed");
        free(body);
        return;
    }
    free(body);
    lantern_log_info(
        "metrics",
        &(const struct lantern_log_metadata){.peer = peer_text},
        "%s %s -> 200",
        method,
        path);
}

static void *lantern_metrics_thread(void *arg) {
    struct lantern_metrics_server *server = arg;
    while (server->running) {
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        int client_fd = accept(server->listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (client_fd < 0) {
            if (!server->running) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            lantern_log_error(
                "metrics",
                NULL,
                "accept failed errno=%d",
                errno);
            continue;
        }
        handle_metrics_request(server, client_fd, &peer);
        close(client_fd);
    }
    return NULL;
}

void lantern_metrics_server_init(struct lantern_metrics_server *server) {
    if (!server) {
        return;
    }
    memset(server, 0, sizeof(*server));
    server->listen_fd = -1;
    server->running = 0;
    server->thread_started = 0;
    server->port = 0;
}

void lantern_metrics_server_reset(struct lantern_metrics_server *server) {
    if (!server) {
        return;
    }
    lantern_metrics_server_stop(server);
    lantern_metrics_server_init(server);
}

int lantern_metrics_server_start(
    struct lantern_metrics_server *server,
    uint16_t port,
    const struct lantern_metrics_callbacks *callbacks) {
    if (!server || !callbacks || !callbacks->snapshot) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        lantern_log_error("metrics", NULL, "socket creation failed errno=%d", errno);
        return -1;
    }

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        lantern_log_warn("metrics", NULL, "setsockopt(SO_REUSEADDR) failed errno=%d", errno);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        lantern_log_error("metrics", NULL, "bind failed errno=%d", errno);
        close(fd);
        return -1;
    }
    if (listen(fd, 16) != 0) {
        lantern_log_error("metrics", NULL, "listen failed errno=%d", errno);
        close(fd);
        return -1;
    }

    server->listen_fd = fd;
    server->callbacks = *callbacks;
    server->port = port;
    server->running = 1;
    server->thread_started = 0;

    int rc = pthread_create(&server->thread, NULL, lantern_metrics_thread, server);
    if (rc != 0) {
        lantern_log_error("metrics", NULL, "pthread_create failed rc=%d", rc);
        close(fd);
        server->listen_fd = -1;
        server->running = 0;
        return -1;
    }
    server->thread_started = 1;
    lantern_log_info(
        "metrics",
        NULL,
        "metrics server listening port=%" PRIu16,
        server->port);
    return 0;
}

void lantern_metrics_server_stop(struct lantern_metrics_server *server) {
    if (!server) {
        return;
    }
    if (server->running) {
        server->running = 0;
        if (server->listen_fd >= 0) {
            shutdown(server->listen_fd, SHUT_RDWR);
        }
    }
    if (server->thread_started) {
        pthread_join(server->thread, NULL);
        server->thread_started = 0;
    }
    if (server->listen_fd >= 0) {
        close(server->listen_fd);
        server->listen_fd = -1;
    }
}
