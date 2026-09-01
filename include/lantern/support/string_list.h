#ifndef LANTERN_SUPPORT_STRING_LIST_H
#define LANTERN_SUPPORT_STRING_LIST_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * An owning list of unique or repeated null-terminated strings.
     *
     * Use only this module to change fields. Synchronize shared mutable access.
     */
    struct lantern_string_list
    {
        /** Owned string pointers. */
        char **items;

        /** Number of initialized string pointers. */
        size_t len;

        /** Number of allocated pointer entries. */
        size_t capacity;
    };

    /** Initialize an empty list. */
    void lantern_string_list_init(struct lantern_string_list *list);

    /** Release all strings and restore an empty list. */
    void lantern_string_list_reset(struct lantern_string_list *list);

    /** Append an owned copy of value and return zero on success. */
    int lantern_string_list_append(struct lantern_string_list *list,
                                   const char *value);

    /** Append value when it is nonempty and absent, and return zero on success.
     */
    int lantern_string_list_append_unique(struct lantern_string_list *list,
                                          const char *value);

    /** Return true when the list contains value. */
    bool lantern_string_list_contains(const struct lantern_string_list *list,
                                      const char *value);

    /** Remove the first matching value and return true when it existed. */
    bool lantern_string_list_remove(struct lantern_string_list *list,
                                    const char *value);

    /**
     * Replace dst with an owned copy of src and return zero on success.
     *
     * A failed copy leaves dst unchanged. A self-copy has no effect.
     */
    int lantern_string_list_copy(struct lantern_string_list *dst,
                                 const struct lantern_string_list *src);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_SUPPORT_STRING_LIST_H */
