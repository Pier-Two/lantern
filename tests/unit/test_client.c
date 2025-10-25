#include "lantern/client.h"
#include <assert.h>

int main(void) {
    struct lantern_client client;
    assert(lantern_init(&client) == 0);
    lantern_shutdown(&client);
    return 0;
}
