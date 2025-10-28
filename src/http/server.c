#include "lantern/http/server.h"

#include "lantern/http/common.h"
#include "lantern/support/log.h"
#include "lantern/support/strings.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define LANTERN_HTTP_BUFFER_SIZE 4096

static void root_to_hex(const LanternRoot *root, char *out, size_t out_len) {
    if (!root || !out || out_len < (2 * LANTERN_ROOT_SIZE) + 3) {
        if (out && out_len > 0) {
            out[0] = '\0';
        }
        return;
    }
    if (lantern_bytes_to_hex(root->bytes, LANTERN_ROOT_SIZE, out, out_len, 1) != 0) {
        if (out_len > 0) {
            out[0] = '\0';
        }
    }
}

static int send_simple_json(int fd, int status_code, const char *status_text, const char *json_body) {
    size_t len = json_body ? strlen(json_body) : 0;
    if (lantern_http_send_response(fd, status_code, status_text, "application/json", json_body, len) != 0) {
        return -1;
    }
    return status_code;
}

static int handle_get_head(struct lantern_http_server *server, int client_fd) {
    if (!server->callbacks.snapshot_head) {
        return send_simple_json(
            client_fd,
            501,
            "Not Implemented",
            "{\"error\":\"head query unsupported\"}");
    }
    struct lantern_http_head_snapshot snapshot;
    if (server->callbacks.snapshot_head(server->callbacks.context, &snapshot) != 0) {
        return send_simple_json(
            client_fd,
            503,
            "Service Unavailable",
            "{\"error\":\"head snapshot unavailable\"}");
    }
    char head_hex[2 * LANTERN_ROOT_SIZE + 3];
    char justified_hex[2 * LANTERN_ROOT_SIZE + 3];
    char finalized_hex[2 * LANTERN_ROOT_SIZE + 3];
    root_to_hex(&snapshot.head_root, head_hex, sizeof(head_hex));
    root_to_hex(&snapshot.justified.root, justified_hex, sizeof(justified_hex));
    root_to_hex(&snapshot.finalized.root, finalized_hex, sizeof(finalized_hex));

    char body[512];
    int len = snprintf(
        body,
        sizeof(body),
        "{"
        "\"slot\":%" PRIu64 ","
        "\"head_root\":\"%s\","
        "\"justified\":{\"slot\":%" PRIu64 ",\"root\":\"%s\"},"
        "\"finalized\":{\"slot\":%" PRIu64 ",\"root\":\"%s\"}"
        "}",
        snapshot.slot,
        head_hex,
        snapshot.justified.slot,
        justified_hex,
        snapshot.finalized.slot,
        finalized_hex);
    if (len < 0 || (size_t)len >= sizeof(body)) {
        return send_simple_json(
            client_fd,
            500,
            "Internal Server Error",
            "{\"error\":\"head response too large\"}");
    }
    if (lantern_http_send_response(client_fd, 200, "OK", "application/json", body, (size_t)len) != 0) {
        return -1;
    }
    return 200;
}

static int handle_get_validators(struct lantern_http_server *server, int client_fd) {
    if (!server->callbacks.validator_count || !server->callbacks.validator_info) {
        return send_simple_json(
            client_fd,
            501,
            "Not Implemented",
            "{\"error\":\"validator listing unsupported\"}");
    }
    size_t count = server->callbacks.validator_count(server->callbacks.context);
    char *dynamic_body = NULL;
    size_t capacity = 512;
    dynamic_body = malloc(capacity);
    if (!dynamic_body) {
        return send_simple_json(
            client_fd,
            500,
            "Internal Server Error",
            "{\"error\":\"allocator failure\"}");
    }
    size_t offset = 0;
    int written = snprintf(dynamic_body, capacity, "{\"validators\":[");
    if (written < 0) {
        free(dynamic_body);
        return send_simple_json(
            client_fd,
            500,
            "Internal Server Error",
            "{\"error\":\"formatting failure\"}");
    }
    offset += (size_t)written;
    for (size_t i = 0; i < count; ++i) {
        struct lantern_http_validator_info info;
        if (server->callbacks.validator_info(server->callbacks.context, i, &info) != 0) {
            free(dynamic_body);
            return send_simple_json(
                client_fd,
                503,
                "Service Unavailable",
                "{\"error\":\"validator snapshot unavailable\"}");
        }
        char entry[256];
        int entry_len = snprintf(
            entry,
            sizeof(entry),
            "%s{\"index\":%" PRIu64 ",\"enabled\":%s,\"label\":\"%s\"}",
            i > 0 ? "," : "",
            info.global_index,
            info.enabled ? "true" : "false",
            info.label);
        if (entry_len < 0) {
            free(dynamic_body);
            return send_simple_json(
                client_fd,
                500,
                "Internal Server Error",
                "{\"error\":\"formatting failure\"}");
        }
        size_t needed = offset + (size_t)entry_len + 2;
        if (needed > capacity) {
            size_t new_capacity = capacity * 2;
            while (needed > new_capacity) {
                new_capacity *= 2;
            }
            char *resized = realloc(dynamic_body, new_capacity);
            if (!resized) {
                free(dynamic_body);
                return send_simple_json(
                    client_fd,
                    500,
                    "Internal Server Error",
                    "{\"error\":\"allocator failure\"}");
            }
            dynamic_body = resized;
            capacity = new_capacity;
        }
        memcpy(dynamic_body + offset, entry, (size_t)entry_len);
        offset += (size_t)entry_len;
    }
    if (offset + 2 > capacity) {
        char *resized = realloc(dynamic_body, capacity + 2);
        if (!resized) {
            free(dynamic_body);
            return send_simple_json(
                client_fd,
                500,
                "Internal Server Error",
                "{\"error\":\"allocator failure\"}");
        }
        dynamic_body = resized;
        capacity += 2;
    }
    dynamic_body[offset++] = ']';
    dynamic_body[offset++] = '}';
    int rc = lantern_http_send_response(client_fd, 200, "OK", "application/json", dynamic_body, offset);
    free(dynamic_body);
    if (rc != 0) {
        return -1;
    }
    return 200;
}

static int handle_post_validator_action(
    struct lantern_http_server *server,
    int client_fd,
    const char *path) {
    if (!server->callbacks.set_validator_status) {
        return send_simple_json(
            client_fd,
            501,
            "Not Implemented",
            "{\"error\":\"validator control unsupported\"}");
    }
    const char *prefix = "/lean/v1/validators/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return send_simple_json(
            client_fd,
            404,
            "Not Found",
            "{\"error\":\"unknown validator path\"}");
    }
    const char *rest = path + prefix_len;
    if (!*rest) {
        return send_simple_json(
            client_fd,
            400,
            "Bad Request",
            "{\"error\":\"missing validator index\"}");
    }
    char *endptr = NULL;
    errno = 0;
    uint64_t index = strtoull(rest, &endptr, 10);
    if (errno != 0 || rest == endptr) {
        return send_simple_json(
            client_fd,
            400,
            "Bad Request",
            "{\"error\":\"invalid validator index\"}");
    }
    if (!endptr || *endptr != '/') {
        return send_simple_json(
            client_fd,
            400,
            "Bad Request",
            "{\"error\":\"missing validator action\"}");
    }
    const char *action = endptr + 1;
    bool enable = false;
    if (strcmp(action, "activate") == 0) {
        enable = true;
    } else if (strcmp(action, "deactivate") == 0) {
        enable = false;
    } else {
        return send_simple_json(
            client_fd,
            404,
            "Not Found",
            "{\"error\":\"unknown validator action\"}");
    }

    if (server->callbacks.set_validator_status(server->callbacks.context, index, enable) != 0) {
        return send_simple_json(
            client_fd,
            404,
            "Not Found",
            "{\"error\":\"validator not found\"}");
    }
    if (lantern_http_send_response(client_fd, 204, "No Content", "application/json", NULL, 0) != 0) {
        return -1;
    }
    return 204;
}

static int dispatch_request(
    struct lantern_http_server *server,
    int client_fd,
    const char *method,
    const char *path) {
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/lean/v1/head") == 0) {
            return handle_get_head(server, client_fd);
        }
        if (strcmp(path, "/lean/v1/validators") == 0) {
            return handle_get_validators(server, client_fd);
        }
    } else if (strcmp(method, "POST") == 0) {
        return handle_post_validator_action(server, client_fd, path);
    }
    return send_simple_json(
        client_fd,
        404,
        "Not Found",
        "{\"error\":\"unknown endpoint\"}");
}

static void handle_client_connection(
    struct lantern_http_server *server,
    int client_fd,
    const struct sockaddr_in *peer_addr) {
    char buffer[LANTERN_HTTP_BUFFER_SIZE];
    ssize_t received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return;
    }
    buffer[received] = '\0';

    char method[8];
    char path[256];
    if (sscanf(buffer, "%7s %255s", method, path) != 2) {
        send_simple_json(
            client_fd,
            400,
            "Bad Request",
            "{\"error\":\"malformed request\"}");
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
    int status = dispatch_request(server, client_fd, method, path);
    int http_status = status >= 100 ? status : 500;
    if (status < 0) {
        lantern_log_error(
            "http",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "%s %s failed", method, path);
    } else {
        lantern_log_info(
            "http",
            &(const struct lantern_log_metadata){.peer = peer_text},
            "%s %s -> %d",
            method,
            path,
            http_status);
    }
}

static void *lantern_http_server_thread(void *arg) {
    struct lantern_http_server *server = arg;
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
                "http",
                &(const struct lantern_log_metadata){0},
                "accept failed errno=%d",
                errno);
            continue;
        }
        handle_client_connection(server, client_fd, &peer);
        close(client_fd);
    }
    return NULL;
}

void lantern_http_server_init(struct lantern_http_server *server) {
    if (!server) {
        return;
    }
    memset(server, 0, sizeof(*server));
    server->listen_fd = -1;
    server->running = 0;
    server->thread_started = 0;
    server->port = 0;
}

void lantern_http_server_reset(struct lantern_http_server *server) {
    if (!server) {
        return;
    }
    lantern_http_server_stop(server);
    lantern_http_server_init(server);
}

int lantern_http_server_start(struct lantern_http_server *server, const struct lantern_http_server_config *config) {
    if (!server || !config) {
        return -1;
    }
    if (!config->callbacks.snapshot_head
        || !config->callbacks.validator_count
        || !config->callbacks.validator_info
        || !config->callbacks.set_validator_status) {
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        lantern_log_error("http", NULL, "failed to create socket errno=%d", errno);
        return -1;
    }
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        lantern_log_warn("http", NULL, "setsockopt(SO_REUSEADDR) failed errno=%d", errno);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(config->port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        lantern_log_error("http", NULL, "bind failed errno=%d", errno);
        close(fd);
        return -1;
    }

    if (listen(fd, 16) != 0) {
        lantern_log_error("http", NULL, "listen failed errno=%d", errno);
        close(fd);
        return -1;
    }

    server->listen_fd = fd;
    server->callbacks = config->callbacks;
    server->port = config->port;
    server->running = 1;
    server->thread_started = 0;
    int create_rc = pthread_create(&server->thread, NULL, lantern_http_server_thread, server);
    if (create_rc != 0) {
        lantern_log_error("http", NULL, "pthread_create failed rc=%d", create_rc);
        close(fd);
        server->listen_fd = -1;
        server->running = 0;
        return -1;
    }
    server->thread_started = 1;
    lantern_log_info(
        "http",
        NULL,
        "http server listening port=%" PRIu16,
        server->port);
    return 0;
}

void lantern_http_server_stop(struct lantern_http_server *server) {
    if (!server) {
        return;
    }
    int listen_fd = server->listen_fd;
    if (server->running) {
        server->running = 0;
    }
    if (listen_fd >= 0) {
        shutdown(listen_fd, SHUT_RDWR);
        close(listen_fd);
        server->listen_fd = -1;
    }
    if (server->thread_started) {
        pthread_join(server->thread, NULL);
        server->thread_started = 0;
    }
    server->listen_fd = -1;
}
