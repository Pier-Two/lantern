#include "lantern/client.h"

int lantern_init(struct lantern_client *client) {
    if (!client) {
        return -1;
    }

    client->placeholder = 0;
    return 0;
}

void lantern_shutdown(struct lantern_client *client) {
    (void)client;
}
