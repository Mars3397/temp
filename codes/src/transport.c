#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    // Check the validity of the function arguments
    if (!net || !self || !segm) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        reture NULL;
    }

    // Check if the segment length is valid
    if (segm_len < sizeof(struct tcphdr)) {
        fprintf(stderr, "Invalid TCP segment length.\n");
        return NULL;
    }

    // Copy TCP header from the segment
    memcpy(&self->thdr, segm, sizeof(struct tcphdr));
    
    // Calculate TCP header length
    self->hdrlen = self->thdr.doff * 4;
    if (self->hdrlen < sizeof(struct tcphdr)) {
        fprintf(stderr, "Invalid TCP header length.\n");
        return NULL;
    }

    // Calculate the length of TCP payload
    self->plen = segm_len - self->hdrlen;
    if (self->plen < 0) {
        fprintf(stderr, "Invalid TCP payload length.\n");
        return NULL;
    }

    // Allocate memory for TCP payload
    self->pl = (uint8_t *)malloc(self->plen);
    if (!self->pl) {
        fprintf(stderr, "Failed to allocate memory for TCP payload.\n");
        return NULL;
    }
    // Copy TCP payload from the segment
    memcpy(self->pl, segm + self->hdrlen, self->plen);

    // Return TCP payload
    return self->pl;
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

