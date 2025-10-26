#include "lantern/support/strings.h"

#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *lantern_string_duplicate(const char *source) {
    if (!source) {
        return NULL;
    }
    return lantern_string_duplicate_len(source, strlen(source));
}

char *lantern_string_duplicate_len(const char *source, size_t length) {
    if (!source) {
        return NULL;
    }
    char *copy = malloc(length + 1);
    if (!copy) {
        return NULL;
    }
    memcpy(copy, source, length);
    copy[length] = '\0';
    return copy;
}

char *lantern_trim_whitespace(char *value) {
    if (!value) {
        return NULL;
    }
    while (*value && isspace((unsigned char)*value)) {
        ++value;
    }
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)*(end - 1))) {
        --end;
    }
    *end = '\0';
    return value;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int lantern_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    if (!hex || !out || out_len == 0) {
        return -1;
    }

    while (*hex && isspace((unsigned char)*hex)) {
        ++hex;
    }
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        hex += 2;
    }

    size_t hex_len = strlen(hex);
    while (hex_len > 0 && isspace((unsigned char)hex[hex_len - 1])) {
        --hex_len;
    }

    if (hex_len != out_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
