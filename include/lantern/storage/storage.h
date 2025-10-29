#ifndef LANTERN_STORAGE_STORAGE_H
#define LANTERN_STORAGE_STORAGE_H

#include <stddef.h>

#include "lantern/consensus/containers.h"
#include "lantern/consensus/state.h"
#include "lantern/networking/messages.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*lantern_storage_block_visitor_fn)(
    const LanternSignedBlock *block,
    const LanternRoot *root,
    void *context);

int lantern_storage_prepare(const char *data_dir);
int lantern_storage_save_state(const char *data_dir, const LanternState *state);
int lantern_storage_load_state(const char *data_dir, LanternState *state);
int lantern_storage_save_votes(const char *data_dir, const LanternState *state);
int lantern_storage_load_votes(const char *data_dir, LanternState *state);
int lantern_storage_store_block(const char *data_dir, const LanternSignedBlock *block);
int lantern_storage_collect_blocks(
    const char *data_dir,
    const LanternRoot *roots,
    size_t root_count,
    LanternBlocksByRootResponse *out_blocks);
int lantern_storage_iterate_blocks(
    const char *data_dir,
    lantern_storage_block_visitor_fn visitor,
    void *context);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_STORAGE_STORAGE_H */
