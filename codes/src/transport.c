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
    
    // Calculate the TCP pseudo-header checksum
    uint32_t sum = 0;
    sum += (iphdr.saddr >> 16) & 0xFFFF; // Add the source IP address (upper 16 bits)
    sum += iphdr.saddr & 0xFFFF;         // Add the source IP address (lower 16 bits)
    sum += (iphdr.daddr >> 16) & 0xFFFF; // Add the destination IP address (upper 16 bits)
    sum += iphdr.daddr & 0xFFFF;         // Add the destination IP address (lower 16 bits)
    sum += IPPROTO_TCP;                  // Add the protocol number (TCP)
    sum += tcphdr.th_off * 4 + plen;     // Add the length of the TCP header and payload

    // Calculate the TCP header and payload checksum
    int tcphdr_len = tcphdr.th_off * 4; // Calculate the length of the TCP header
    uint8_t *buf = (uint8_t *)malloc((tcphdr_len + plen) * sizeof(uint8_t)); // Create a buffer to store the TCP header and payload
    memcpy(buf, &tcphdr, tcphdr_len); // Copy the TCP header to the buffer
    memcpy(buf + tcphdr_len, pl, plen); // Copy the payload to the buffer, starting at the midpoint of the buffer

    uint16_t buffer[(tcphdr_len + plen) / 2];
    memcpy(buffer, &buf, (tcphdr_len + plen) / 2);
    for (int i = 0; i < (tcphdr_len + plen) / 2; i++) { // Loop over the buffer, 16 bits at a time
        sum += buffer[i]; // Add each 16-bit value to the checksum, after converting to host byte order
    }
    if ((tcphdr_len + plen) % 2 == 1) { // If the length of the TCP header and payload is odd
        uint16_t last = ((uint8_t *)buffer)[tcphdr_len + plen - 1]; // Get the last byte of the buffer
        sum += last << 8; // Add the last byte to the checksum, shifted left by 8 bits
    }

    free(buf);

    // Calculate the final checksum
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the one's complement of the sum to get the final checksum
    return ~sum; 
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    // Check the validity of the function arguments
    if (!net || !self || !segm) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
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
        fprintf(stderr, "Invalid TCP header length (%d).\n", self->hdrlen);
        return NULL;
    }

    // Calculate the length of TCP payload
    self->plen = segm_len - self->hdrlen;
    // printf("tcp payload length: %d\n", self->plen);
    if (self->plen < 0) {
        fprintf(stderr, "Invalid TCP payload length.\n");
        return NULL;
    }

    // Allocate memory for TCP payload
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
    
    // Hint 2
    // Fill up the TCP header
    self->thdr.seq = htonl(self->x_tx_seq);
    self->thdr.ack_seq = htonl(self->x_tx_ack);
    self->thdr.psh = 1;
    memcpy(self->pl, data, dlen);
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, self->pl, dlen);

    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}

