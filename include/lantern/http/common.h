#ifndef LANTERN_HTTP_COMMON_H
#define LANTERN_HTTP_COMMON_H

#include <stddef.h>

int lantern_http_send_all(int fd, const char *data, size_t length);
int lantern_http_send_response(
    int fd,
    int status_code,
    const char *status_text,
    const char *content_type,
    const char *body,
    size_t body_len);

#endif /* LANTERN_HTTP_COMMON_H */
