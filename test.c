#include <stdio.h>
#include "codes/include/esp.h"

int main() {
    uint8_t key[16];
    get_ik(SADB_SATYPE_ESP, key);

    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    print("\n");

    return 0;
}