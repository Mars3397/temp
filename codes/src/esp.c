#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

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
        ext = (struct sadb_ext *)((char *)ext + PFKEY_ALIGN8(ext->sadb_ext_len) * 8);
    }

    close(sock_fd);
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0;  // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1) {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    // Check the validity of the function arguments
    if (!self || !esp_pkt) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        reture NULL;
    }

    // Check if the packet length is valid
    if (esp_len < sizeof(EspHeader) + sizeof(EspTrailer)) {
        fprintf(stderr, "Invalid ESP packet length.\n");
        return NULL;
    }

    // Copy ESP header from the packet
    memcpy(&self->hdr, esp_pkt, sizeof(EspHeader));
    esp_pkt += sizeof(EspHeader);
    esp_len -= sizeof(EspHeader);

    // Copy ESP trailer from the packet
    memcpy(&self->tlr, esp_pkt + esp_len - sizeof(EspTrailer), sizeof(EspTrailer));

    // Allocate memory for ESP padding
    self->pad = (uint8_t *)malloc(self->tlr.pad_len);
    if (!self->pad) {
        fprintf(stderr, "Failed to allocate memory for ESP padding.\n");
        return NULL;
    }
    // Copy ESP padding from the packet
    memcpy(self->pad, esp_pkt + esp_len - sizeof(EspTrailer) - self->tlr.pad_len, self->tlr.pad_len);
    
    // Get ESP payload length from the padding length field in the trailer
    self->plen = esp_len - sizeof(EspTrailer) - self->tlr.pad_len;

    // Allocate memory for ESP payload
    self->pl = (uint8_t *)malloc(self->plen);
    if (!self->pl) {
        fprintf(stderr, "Failed to allocate memory for ESP payload.\n");
        return NULL;
    }
    // Copy ESP payload from the packet
    memcpy(self->pl, esp_pkt, self->plen);

    return self->pl;
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
