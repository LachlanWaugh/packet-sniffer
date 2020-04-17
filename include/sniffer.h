#ifndef SNIFFER_H
#define SNIFFER_H

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <sys/socket.h>

FILE *output_stream;
int filtered, passive, packets_to_read;
int port_filters[100];
int packet_filters[5];

int request_user_settings(void);
int request_output_file(void);
int request_packets_to_read(void);
int request_passive(void);
int request_filtering(void);

int create_sniffer(pcap_t **device_handle);

#endif
