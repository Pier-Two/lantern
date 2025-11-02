#include "lantern/networking/enr.h"
#include "lantern/networking/libp2p.h"

#include <stdint.h>

static const uint8_t kHostSecret[32] = {
    0xb7, 0x1c, 0x71, 0xa6, 0x7e, 0x11, 0x77, 0xad,
    0x4e, 0x90, 0x16, 0x95, 0xe1, 0xb4, 0xb9, 0xee,
    0x17, 0xae, 0x16, 0xc6, 0x66, 0x8d, 0x31, 0x3e,
    0xac, 0x2f, 0x96, 0xdb, 0xcd, 0xa3, 0xf2, 0x91,
};

static const char *kQuicOnlyEnr =
    "enr:-IW4QKbT-CoCAKBpbYNfzfFcPfYjkqHyH-5sFlVkaKlNEPN1M5M34vIYb8HyCg56m7-V13pKWZqH9ThdYtXjjavDrP4BgmlkgnY0"
    "gmlwhKwUAAqEcXVpY4IjKIlzZWNwMjU2azGhAuIbyETf2xNYGNJfCPhn95r0lyyoRpB5PCWwh53RSSgS";

int main(void) {
    struct lantern_enr_record record;
    lantern_enr_record_init(&record);

    struct lantern_libp2p_host host;
    lantern_libp2p_host_init(&host);

    struct lantern_libp2p_config config = {
        .listen_multiaddr = "/ip4/127.0.0.1/udp/9310/quic-v1",
        .secp256k1_secret = kHostSecret,
        .secret_len = sizeof(kHostSecret),
    };

    if (lantern_enr_record_decode(kQuicOnlyEnr, &record) != 0) {
        lantern_enr_record_reset(&record);
        return 1;
    }

    if (lantern_libp2p_host_start(&host, &config) != 0) {
        lantern_enr_record_reset(&record);
        lantern_libp2p_host_reset(&host);
        return 1;
    }

    int rc = lantern_libp2p_host_add_enr_peer(&host, &record, 1000);

    lantern_enr_record_reset(&record);
    lantern_libp2p_host_reset(&host);

    return rc == 0 ? 0 : 1;
}
