#include <stdio.h>
#include <stdint.h>
#include "linux/pfkeyv2.h"

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)
    
    int sock_fd, err;
    struct sadb_msg msg;
    struct sadb_sa sa;
    struct sadb_address src, dst;
    struct iovec iov;
    struct msghdr msg_hdr;
    char buf[4096];

    // Create a PF_KEY socket
    sock_fd = socket(AF_KEY, SOCK_RAW, PF_KEY_V2);
    if (sock_fd < 0) {
        perror("socket");
        return;
    }

    // Construct a SADB_GET message to retrieve the authentication key
    memset(&msg, 0, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_GET;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8;
    memset(&sa, 0, sizeof(sa));
    sa.sadb_sa_len = sizeof(sa) / 8;
    sa.sadb_sa_exttype = SADB_EXT_SA;
    memset(&src, 0, sizeof(src));
    src.sadb_address_len = sizeof(src) / 8;
    src.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
    memset(&dst, 0, sizeof(dst));
    dst.sadb_address_len = sizeof(dst) / 8;
    dst.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
    memset(&iov, 0, sizeof(iov));
    iov.iov_base = &msg;
    iov.iov_len = sizeof(msg);
    memset(&msg_hdr, 0, sizeof(msg_hdr));
    msg_hdr.msg_name = NULL;
    msg_hdr.msg_namelen = 0;
    msg_hdr.msg_iov = &iov;
    msg_hdr.msg_iovlen = 1;

    // Send the SADB_GET message to the kernel
    err = sendmsg(sock_fd, &msg_hdr, 0);
    if (err < 0) {
        perror("sendmsg");
        close(sock_fd);
        return;
    }

    // Receive the SADB_GET message response from the kernel
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    err = recvmsg(sock_fd, &msg_hdr, 0);
    if (err < 0) {
        perror("recvmsg");
        close(sock_fd);
        return;
    }

    // Parse the SADB_GET message response to retrieve the authentication key
    struct sadb_ext *ext = (struct sadb_ext *)(buf + sizeof(struct sadb_msg));
    while ((char *)ext < buf + err) {
        if (ext->sadb_ext_type == SADB_EXT_KEY_AUTH) {
            struct sadb_key *key_ext = (struct sadb_key *)ext;
            memcpy(key, (char *)key_ext + sizeof(struct sadb_key), key_ext->sadb_key_bits / 8);
            break;
        }
        ext = (struct sadb_ext *)((char *)ext + PFKEY_ALIGN8LEN(ext->sadb_ext_len) * 8);
    }

    close(sock_fd);
}

int main() {
    uint8_t key[16];
    get_ik(SADB_SATYPE_ESP, key);

    printf("ESP Authentication Key: ");
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}

