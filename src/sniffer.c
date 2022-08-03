#include "sniffer.h"

/* */
int sniffer_create(pcap_t **device_handle) {
    pcap_if_t *device_list, *device;

    char errbuf[PCAP_ERRBUF_SIZE], devices[100][100], *device_name;
    int count = 0, device_number, error;

    /* obtain a list of available devices */
    printf("finding all available devices on your system ... ");
    error = pcap_findalldevs(&device_list, errbuf);
    if (error) {
        fprintf(stderr, "Failed: device '%s' could not be found.\n", errbuf);
        return 1;
    }

    /* print a list of available devices */
    printf("available devices found: \n");
    for (device = device_list; device && count < 100; device = device->next) {
        if (device->name) {
            strncpy(devices[count], device->name, 100);
            printf("%d. %-12s\t- %s\n", count, device->name, device->description);
            ++count;
        }
    }
    printf("\n");

    /* Ask the user which device they would like to use to perform the sniffing */
    printf("enter the number of the device you would like to sniff:\n");
    scanf("%d", &device_number);
    device_name = devices[device_number];

    /* Open the sniffer */
    *device_handle = pcap_open_live(device_name, 65536, 1, 0, errbuf);
    if (*device_handle == NULL) {
        fprintf(stderr, "ERROR: device '%s' could not be opened.\n\t%s\n", device_name, errbuf);
        return 1;
    }
    printf("\n");

    /* If the user requested for filters to be added, apply them */
    if (filtered) {
        struct bpf_program fp;
        bpf_u_int32 net = 0x0; // to surpress unitialized warnings
        char filter[100];
        
        for (int i = 0; port_filters[i]; i++) {
            snprintf(filter, 11, "port %d", port_filters[i]);
            
            /*
            * Compile filter statements from user input into actual filters 
            * This uses Berkely Packet Filters
            */
            error = pcap_compile(*device_handle, &fp, filter, 0, net);
            if (error == -1) {
                fprintf(stderr, "Failed: couldn't parse filter 'port %s'.\n\t%s\n", filter, pcap_geterr(*device_handle));
                return 1;
            }
            
            /* Apply the filters */
            error = pcap_setfilter(*device_handle, &fp);
            if (error == -1) {
                fprintf(stderr, "Failed: couldn't install filter 'port %s'.\n\t%s\n", filter, pcap_geterr(*device_handle));
                return 1;
            }
        }
    }
    
    return 0;
}

/* */
int sniffer_delete(pcap_t **device_handle) {
    /* If the user opened a log file, close it */
    if (output_stream != stdout) {
        fclose(output_stream);
    }
}

/*
    Log file:
    Filtered/Unfiltered:
    Passive/Active:
*/
int request_opt(void) {
    char user_input[64];
    
    /*
        Ask the user whether they would like to change the settings for the
        sniffer, or use the default settings (stdout, passive, unfiltered)
    */
    printf("Do you want to manually configure the sniffer, or use default settings?\
    \nType 'manual' to configure the settings, or 'skip' for default.\n");
    scanf("%63s", user_input);
    printf("\n");
    
    if (strcmp(user_input, "skip") == 0) {
        output_stream = fopen("log_file.txt", "w");
        packets_to_read = 100;
        filtered = 0;
        passive = 1;
        return 0;
    }

    /* */
    if (request_ostream()) {
        return ERR_CODE;
    } else if (request_npackets()) {
        return ERR_CODE;
    } else if (request_passive()) {
        return ERR_CODE;
    } else if (request_filters()) {
        return ERR_CODE;
    }
    
    return 0;
}

int request_ostream(void) {
    char user_input[64];
    
    /*
    * Ask the user where they how they would like to receive the packets read
    * (either written to a log file, or printed to the console)
    */
    printf("Please enter the log file that you would like the packets to be written to.\
    \nIf you would like the program to print to the console, type 'skip'.\n");
    scanf("%63s", user_input);

    /* If the user provided a filename, open the file */
    if (strcmp(user_input, "skip") == 0) {
        output_stream = stdout;
        printf("logging to: console\n");
    } else {
        if ((output_stream = fopen(user_input, "w"))) {
            printf("logging to: %s\n", user_input);
        } else {
            fprintf(stderr, "ERROR: invalid log file.\n");
            return 1;
        }
    }
    printf("\n");
    
    return 0;
}

int request_packets_to_read(void) {
    char user_input[64];
    
    /* 
    * Ask the user how many packets they would like to receive, it is
    * read as a string simply for error handling.
    */
    printf("how many packets would you like to read?\nChoose a number in the range [0, 1000)\n");
    scanf("%63s", user_input);

    packets_to_read = atoi(user_input);
    if (packets_to_read > 1000) {
        fprintf(stderr, "a maximum of 1000 packets can be read.\n");
        return 1;
    } else if (packets_to_read <= 0) {
        fprintf(stderr, "ERROR: invalid number of packets requested, aborting.\n");
        return 1;
    }

    printf("preparing to read %d packets.\n\n", packets_to_read);
    return 0;
}

int request_passive(void) {
    char user_input[64];

    /*
    * Ask the user whether they would like to initiate passive sniffing, or
    * active sniffing
    */
    printf("would you like to perform passive [P] or active [A] sniffing?\n");
    scanf("%63s", user_input);

    /* Check that the user provided valid input */
    if (user_input[0] == "A") {
        printf("performing active sniffing.\n");
        passive = 0;
    } else if (user_input[0] == "P") {
        printf("performing passive sniffing.\n");
        passive = 1;
    } else {
        fprintf(stderr, "invalid command. Exiting.\n");
        return 1;
    }
    printf("\n");
    
    return 0;
}

int request_filtering(void) {
    char user_input[1024], *filter;
    int port_index = 0, port_number;
    
    /* Finally, check whether the user wants to filter for specific packets */
    printf("To setup filtering, please provide a list of filters separated by ',' (no spaces).\
    \nPort filters should be a number in the range [1-1023] e.g. '443,20,21'.\
    \nPacket filters should be one of ['UDP', 'TCP', 'ICMP'] e.g. 'TCP,UDP'.");
    scanf("%1023s", user_input);

    /* Check that the user provided valid input */
    if (strcmp(user_input, "") == 0) {
        printf("Performing unfiltered sniffing.\n");
        filtered = 0;
    } else {
        while ((filter = strtok(user_input, ",")) && port_index < 1024) {
            /* Check if the filter is a port */
            if (strstr(filter, "UDP")) {
                protocols &= UDP;
            } else if (strstr(filter, "TCP")) {
                protocols &= TCP;
            } else if (strstr(filter, "ICMP")) {
                protocols &= ICMP;
            } else {
                port_number = atoi(filter);
                if (port_number <= 0 || port_number > 1023) {
                    fprintf(stderr, "Failed: invalid filter '%s'\n", filter);
                } else {
                    port_filters[port_index++] = port_number;
                }
            }

            filter = strtok(NULL, ",");
        }

        port_filters[port_index] = 0;
        filtered = 1;
    }
    printf("\n");
    
    return 0;
}

/* Resources used
* https://www.oreilly.com/library/view/building-internet-firewalls/1565928717/ch04.html
* https://www.tcpdump.org/pcap.html
* https://www.tcpdump.org/manpages/pcap.3pcap.html
* https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
* https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
* https://gist.github.com/fffaraz/7f9971463558e9ea9545
* https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
* https://opensourceforu.com/2011/02/capturing-packets-c-program-libpcap/
* https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
* https://medium.com/@gauravsarma1992/packet-sniffer-and-parser-in-c-c86070081c38
* http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
*
* https://github.com/m0nad/ARP-Poison/blob/master/arp-poison.c
* https://github.com/SRJanel/arp_poisoning
*/
