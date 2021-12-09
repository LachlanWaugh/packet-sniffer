#ifndef SNIFFER_H
#define SNIFFER_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <sys/socket.h>

FILE *outfile;
int filtered, passive, packets_to_read;
int port_filters[100];

int protocols;
#define UDP  0x1;
#define TCP  0x10;
#define ICMP 0x100;

int request_opt(void);
int request_ostream(void);
int request_npackets(void);
int request_passive(void);
int request_filters(void);

int sniffer_create(pcap_t **device_handle);
int sniffer_delete(pcap_t **device_handle);

#endif
