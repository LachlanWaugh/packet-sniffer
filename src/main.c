#include "sniffer.h"
#include "packet_reader.h"

/* */
int main(void) {
    /* Asks user how they would like the sniffer to grab/store information */
    if (request_opt()) {
        exit(1);
    }

    /* Set up a device to sniff packets */
    pcap_t *device_handle;
    if (sniffer_create(&device_handle)) {
        exit(1);
    }

    /*
        begin sniffing, if the user only wants to perform passive sniffing, 
        just print out however many packets they wanted
    */
    if (passive) { 
        pcap_loop(device_handle, packets_to_read, process_packet, NULL);
    } else { /*  If the user wants to perform active sniffing, enable ARP_Poisoning */
        // TODO: implement active sniffing stuff
    }

    /* */
    sniffer_delete();

    return 0;
}
