#ifndef LANTERN_CORE_CLIENT_COMMON_H
#define LANTERN_CORE_CLIENT_COMMON_H

#include <stddef.h>
#include <stdbool.h>

#include "lantern/core/client.h"

void lantern_client_format_root_hex(const LanternRoot *root, char *out, size_t out_len);
bool lantern_client_lock_state(struct lantern_client *client);
void lantern_client_unlock_state(struct lantern_client *client, bool locked);
bool lantern_client_lock_pending(struct lantern_client *client);
void lantern_client_unlock_pending(struct lantern_client *client, bool locked);
uint64_t lantern_client_wall_time_seconds(void);

#endif /* LANTERN_CORE_CLIENT_COMMON_H */
