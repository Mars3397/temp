#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    uint16_t *buffer = (uint16_t *)&iphdr;
    size_t hdr_len = iphdr.ihl * 4;
    uint32_t sum = 0;

    // Calculate the checksum for the IP header
    for (size_t i = 0; i < hdr_len / 2; i++) {
        sum += buffer[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    // Check the validity of the function arguments
    if (!self || !pkt) {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        reture NULL;
    }
    
    // Check if packet length is greater than or equal to the size of am IP header
    if (pkt_len < sizeof(struct iphdr)) {
        fprintf(stderr, "Packet too short for IP header\n");
        return NULL;
    }

    // Cast the packet as an IP header struct
    struct iphdr *iph = (struct iphdr *)pkt;

    // Set the IP source and destination address
    inet_ntop(AF_INET, &(iph->saddr), self->src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->daddr), self->dst_ip, INET6_ADDRSTRLEN);

    // Set the protocol number and payload length
    self->pro = (Proto)iph->protocol;
    self->plen = ntohs(iph->tot_len) - sizeof(struct iphdr);

    // Return a pointer to the payload
    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)

    return self;
}

void init_net(Net *self)
{
    if (!self) {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
