#ifndef LANTERN_CLIENT_H
#define LANTERN_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

struct lantern_client {
    int placeholder; 
};

int lantern_init(struct lantern_client *client);
void lantern_shutdown(struct lantern_client *client);

#ifdef __cplusplus
}
#endif

#endif /* LANTERN_CLIENT_H */
