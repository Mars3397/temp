#include <stdio.h>
#include "codes/include/esp.h"

int main() {
    uint8_t key[16];
    get_ik(SADB_SATYPE_ESP, key);

    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}

/*
setkey -c <<EOF
add 10.0.0.1 10.0.0.2 esp 12345 -E aes-cbc 0123456789ABCDEF -A hmac-sha1-96 0123456789ABCDEF;
EOF
*/
