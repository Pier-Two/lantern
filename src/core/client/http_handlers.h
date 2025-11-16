#ifndef LANTERN_CORE_CLIENT_HTTP_HANDLERS_H
#define LANTERN_CORE_CLIENT_HTTP_HANDLERS_H

#include <stddef.h>
#include <stdint.h>

#include "lantern/core/client.h"

int lantern_client_http_snapshot_head(void *context, struct lantern_http_head_snapshot *out_snapshot);
size_t lantern_client_http_validator_count_cb(void *context);
int lantern_client_http_validator_info_cb(void *context, size_t index, struct lantern_http_validator_info *out_info);
int lantern_client_http_set_validator_status_cb(void *context, uint64_t global_index, bool enabled);
int lantern_client_metrics_snapshot_cb(void *context, struct lantern_metrics_snapshot *out_snapshot);

#endif /* LANTERN_CORE_CLIENT_HTTP_HANDLERS_H */
