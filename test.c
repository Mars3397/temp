#include <stdio.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "linux/pfkeyv2.h"
#include <stddef.h>

static inline size_t align8(size_t len) {
    return (len + 7) & ~7;
}

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    
    int sock_fd, err;
    struct sadb_msg msg = {
        .sadb_msg_version = PF_KEY_V2,
        .sadb_msg_type = SADB_DUMP,
        .sadb_msg_errno = 0,
        .sadb_msg_satype = type,
        .sadb_msg_len = sizeof(struct sadb_msg) / sizeof(uint64_t),
        .sadb_msg_reserved = 0,
        .sadb_msg_seq = 0,
        .sadb_msg_pid = getpid(),
    };

    // Create a PF_KEY socket
    sock_fd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // Send the SADB_GET message to the kernel
    size_t l = write(sock_fd, &msg, sizeof(struct sadb_msg)); 
    if (l < 0) {
        perror("write");
        close(sock_fd);
        return;
    }

    // Receive the SADB_GET message response from the kernel
    char buf[1024];
    ssize_t len = read(sock_fd, &buf, 1024);
    printf("%ld\n", len);
    if (len < 0) {
        perror("read");
        close(sock_fd);
        return;
    }

    // Parse the SADB_DUMP response to retrieve the authentication key
    struct sadb_ext *ext = (struct sadb_ext *)(buf);
    while ((char *)ext < buf + 216) {
        printf("ext->sadb_ext_type: %d\n", ext->sadb_ext_type);
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key_ext = (struct sadb_key *)ext;
            memcpy(key, (char *)key_ext + sizeof(struct sadb_key), key_ext->sadb_key_bits / 8);
            break;
        }
        ext += sizeof(struct sadb_ext);
    }

    close(sock_fd);
}

int main() {
    uint8_t key[16];
    memset(&key, 0, sizeof(key));
    get_ik(SADB_SATYPE_ESP, key);

    printf("ESP Authentication Key: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}

