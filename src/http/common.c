#include "lantern/http/common.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int lantern_http_send_all(int fd, const char *data, size_t length) {
    if (!data) {
        return -1;
    }
    while (length > 0) {
        ssize_t written = send(fd, data, length, 0);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        data += written;
        length -= (size_t)written;
    }
    return 0;
}

int lantern_http_send_response(
    int fd,
    int status_code,
    const char *status_text,
    const char *content_type,
    const char *body,
    size_t body_len) {
    char header[256];
    const char *text = status_text ? status_text : "OK";
    const char *type = content_type ? content_type : "application/json";
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        text,
        type,
        body ? body_len : 0u);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        return -1;
    }
    if (lantern_http_send_all(fd, header, (size_t)header_len) != 0) {
        return -1;
    }
    if (body && body_len > 0) {
        if (lantern_http_send_all(fd, body, body_len) != 0) {
            return -1;
        }
    }
    return 0;
}
