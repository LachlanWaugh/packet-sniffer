#ifndef PACKET_READER_H
#define PACKET_READER_H

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <netinet/ip_icmp.h>  /* Provides declarations for icmp header */
#include <netinet/udp.h>      /* Provides declarations for udp header  */
#include <netinet/tcp.h>      /* Provides declarations for tcp header  */
#include <netinet/ip.h>       /* Provides declarations for ip header   */

#include "sniffer.h"

struct sockaddr_in source, dest;
// int tcp, udp, icmp, igmp, ip, others, total;

void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

void print_ethernet_header(const u_char *packet, int size);

void print_ip_header(const u_char *packet, int size);

void print_tcp_packet(const u_char *packet, int size);
void print_udp_packet(const u_char *packet, int size);
void print_icmp_packet(const u_char *packet, int size);

void print_data (const u_char *data, int size);

#endif
