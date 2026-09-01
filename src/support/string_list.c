#include "lantern/support/string_list.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lantern/support/strings.h"

void lantern_string_list_init(struct lantern_string_list *list)
{
    if (!list)
    {
        return;
    }

    list->items = NULL;
    list->len = 0;
    list->capacity = 0;
}

void lantern_string_list_reset(struct lantern_string_list *list)
{
    if (!list)
    {
        return;
    }

    if (list->items)
    {
        size_t limit = list->len;
        if (list->capacity > 0 && limit > list->capacity)
        {
            limit = list->capacity;
        }

        for (size_t i = 0; i < limit; ++i)
        {
            free(list->items[i]);
            list->items[i] = NULL;
        }
        free(list->items);
    }

    list->items = NULL;
    list->len = 0;
    list->capacity = 0;
}

static int string_list_reserve(struct lantern_string_list *list,
                               size_t new_capacity)
{
    if (new_capacity <= list->capacity)
    {
        return 0;
    }
    if (new_capacity > SIZE_MAX / sizeof(*list->items))
    {
        return -1;
    }

    size_t adjusted = list->capacity == 0 ? 4 : list->capacity;
    while (adjusted < new_capacity)
    {
        if (adjusted > SIZE_MAX / 2u)
        {
            adjusted = new_capacity;
            break;
        }
        adjusted *= 2u;
    }

    char **items = realloc(list->items, adjusted * sizeof(*items));
    if (!items)
    {
        return -1;
    }

    for (size_t i = list->capacity; i < adjusted; ++i)
    {
        items[i] = NULL;
    }

    list->items = items;
    list->capacity = adjusted;
    return 0;
}

int lantern_string_list_append(struct lantern_string_list *list,
                               const char *value)
{
    if (!list || !value || list->len == SIZE_MAX)
    {
        return -1;
    }

    if (string_list_reserve(list, list->len + 1u) != 0)
    {
        return -1;
    }

    char *copy = lantern_string_duplicate(value);
    if (!copy)
    {
        return -1;
    }

    list->items[list->len++] = copy;
    return 0;
}

bool lantern_string_list_contains(const struct lantern_string_list *list,
                                  const char *value)
{
    if (!list || !value)
    {
        return false;
    }

    for (size_t i = 0; i < list->len; ++i)
    {
        if (list->items[i] && strcmp(list->items[i], value) == 0)
        {
            return true;
        }
    }

    return false;
}

bool lantern_string_list_remove(struct lantern_string_list *list,
                                const char *value)
{
    if (!list || !value)
    {
        return false;
    }

    for (size_t i = 0; i < list->len; ++i)
    {
        if (!list->items[i] || strcmp(list->items[i], value) != 0)
        {
            continue;
        }

        free(list->items[i]);
        if (i + 1u < list->len)
        {
            memmove(&list->items[i], &list->items[i + 1u],
                    (list->len - i - 1u) * sizeof(*list->items));
        }
        list->len -= 1u;
        list->items[list->len] = NULL;
        return true;
    }

    return false;
}

int lantern_string_list_append_unique(struct lantern_string_list *list,
                                      const char *value)
{
    if (!list || !value)
    {
        return -1;
    }

    if (*value == '\0' || lantern_string_list_contains(list, value))
    {
        return 0;
    }

    return lantern_string_list_append(list, value);
}

int lantern_string_list_copy(struct lantern_string_list *dst,
                             const struct lantern_string_list *src)
{
    if (!dst || !src)
    {
        return -1;
    }
    if (dst == src)
    {
        return 0;
    }

    struct lantern_string_list copy;
    lantern_string_list_init(&copy);

    if (src->len > 0 && string_list_reserve(&copy, src->len) != 0)
    {
        return -1;
    }

    for (size_t i = 0; i < src->len; ++i)
    {
        char *item = lantern_string_duplicate(src->items[i]);
        if (!item)
        {
            lantern_string_list_reset(&copy);
            return -1;
        }

        copy.items[copy.len++] = item;
    }

    lantern_string_list_reset(dst);
    *dst = copy;
    return 0;
}
