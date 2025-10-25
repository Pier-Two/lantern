#include "lantern/client.h"
#include <stdio.h>

int main(void) {
    struct lantern_client client;
    if (lantern_init(&client) != 0) {
        fprintf(stderr, "Failed to initialize lantern client\n");
        return 1;
    }

    printf("lantern client bootstrapped successfully\n");

    lantern_shutdown(&client);
    return 0;
}
