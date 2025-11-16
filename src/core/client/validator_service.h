#ifndef LANTERN_CORE_CLIENT_VALIDATOR_SERVICE_H
#define LANTERN_CORE_CLIENT_VALIDATOR_SERVICE_H

#include "lantern/core/client.h"

int lantern_client_start_validator_service(struct lantern_client *client);
void lantern_client_stop_validator_service(struct lantern_client *client);

#endif /* LANTERN_CORE_CLIENT_VALIDATOR_SERVICE_H */
