#include "internal/strings.h"

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
