#include "sniffer.h"

/* */
int create_sniffer(pcap_t **device_handle) {
    pcap_if_t *device_list, *device;

    char errbuf[PCAP_ERRBUF_SIZE], devices[100][100], *device_name;
    int count = 0, device_number, error;

    /* Obtain a list of available devices */
    printf("Finding all available devices on your system ... ");
    error = pcap_findalldevs(&device_list, errbuf);
    if (error) {
        fprintf(stderr, "Failed: device '%s' could not be found.\n", errbuf);
        return 1;
    }
    printf("Success.\n");

    /* Print a list of available devices */
    printf("Available devices found: \n");
    for (device = device_list; device != NULL; device = device->next) {
        if (device->name) {
            strcpy(devices[count], device->name);
        }

        printf("%d. %-12s\t- %s\n", count, device->name, device->description);
        count++;
    }
    printf("\n");

    /* Ask the user which device they would like to use to perform the sniffing */
    printf("Enter the number of the device you would like to sniff:\n");
    scanf("%d", &device_number);
    device_name = devices[device_number];

    /* Open the sniffer */
    *device_handle = pcap_open_live(device_name, 65536, 1, 0, errbuf);
    if (*device_handle == NULL) {
        fprintf(stderr, "Failed: device '%s' could not be opened.\n\t%s\n", device_name, errbuf);
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

/*
* Log file:
* Filtered/Unfiltered:
* Passive/Active:
*/
int request_user_settings(void) {
    char user_input[64];
    int error;

    /*
    * Ask the user whether they would like to change the settings for the
    * sniffer, or use the default settings (stdout, passive, unfiltered)
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
    error = request_output_file();
    if (error) {
        return error;
    }
    
    /* */
    error = request_packets_to_read();
    if (error) {
        return error;
    }
    
    /* */
    error = request_passive();
    if (error) {
        return error;
    }

    /* */
    error = request_filtering();
    if (error) {
        return error;
    }
    
    return 0;
}

int request_output_file(void) {
    char user_input[64];
    
    /*
    * Ask the user where they how they would like to receive the packets read
    * (either written to a log file, or printed to the console)
    */
    printf("Please enter the log file that you would like the packets to be written to.\
    \nIf you would like the program to print to the console, type 'skip'.\n");
    scanf("%63s", user_input);

    /* If the user provided a filename, open the file */
    if (strcmp(user_input, "skip")) {
        output_stream = fopen(user_input, "w");
        /* */
        if (output_stream == NULL) {
            fprintf(stderr, "Failed: Invalid log file.\n");
            return 1;
        }

        printf("Logging to: %s\n", user_input);
    }
    
    else {
        output_stream = stdout;
        printf("Logging to: console\n");
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
    printf("How many packets would you like to read?\n");
    scanf("%63s", user_input);
    
    packets_to_read = atoi(user_input);
    if (packets_to_read > 1000) {
        printf("A maximum of 1000 packets can be read.\n");
        packets_to_read = 1000;
    }
    
    if (packets_to_read <= 0) {
        printf("Failed: invalid number of packets requested, aborting.\n");
        return 1;
    }
    
    printf("Preparing to read %d packets.\n", packets_to_read);
    
    printf("\n");
    return 0;
}

int request_passive(void) {
    char user_input[64];
    
    /*
    * Ask the user whether they would like to initiate passive sniffing, or
    * active sniffing
    */
    printf("Would you like to perform passive sniffing or active sniffing?\n");
    scanf("%63s", user_input);

    /* Check that the user provided valid input */
    if (strcmp(user_input, "active") == 0) {
        printf("Performing active sniffing.\n");
        passive = 0;
    }
    else if (strcmp(user_input, "passive") == 0) {
        printf("Performing passive sniffing.\n");
        passive = 1;
    }
    else {
        printf("Invalid command. Exiting.\n");
        return 1;
    }
    printf("\n");
    return 0;
}

int request_filtering(void) {
    char user_input[1024], *filter;
    int port_index = 0, port_number;
    
    /*
    * Finally, check whether the user wants to filter for specific packets
    */
    printf("To setup filtering, please provide a list of filters separated by ',' (no spaces).\
    \nPort filters should be a number in the range [1-1023] e.g. '1,2,3'.\
    \nPacket filters should be one of ['UDP', 'TCP', 'ICMP'] e.g. 'TCP,UDP'.");
    scanf("%1023s", user_input);

    /* Check that the user provided valid input */
    if (strcmp(user_input, "") == 0) {
        printf("Performing unfiltered sniffing.\n");
        filtered = 0;
    } else {
        filter = strtok(user_input, ",");
        while (filter) {
            /* Check if the filter is a port */
            if (strstr(filter, "UDP")) {
                packet_filters[0] = 1;
            } else if (strstr(filter, "TCP")) {
                packet_filters[1] = 1;
            } else if (strstr(filter, "ICMP")) {
                packet_filters[2] = 1;
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
