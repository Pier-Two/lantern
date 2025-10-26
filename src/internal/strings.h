#ifndef LANTERN_INTERNAL_STRINGS_H
#define LANTERN_INTERNAL_STRINGS_H

#include <stddef.h>

char *lantern_string_duplicate(const char *source);
char *lantern_string_duplicate_len(const char *source, size_t length);

#endif /* LANTERN_INTERNAL_STRINGS_H */
