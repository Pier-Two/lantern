#ifndef LANTERN_CONSENSUS_SIGNATURE_H
#define LANTERN_CONSENSUS_SIGNATURE_H

#include <stdbool.h>
#include <stddef.h>

#include "lantern/consensus/containers.h"

bool lantern_signature_is_zero(const LanternSignature *signature);
void lantern_signature_zero(LanternSignature *signature);

#endif /* LANTERN_CONSENSUS_SIGNATURE_H */
