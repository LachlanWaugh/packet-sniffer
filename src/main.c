#include "sniffer.h"
#include "packet_reader.h"

/*
*
*/
int main(void) {
    int error = 0;
    
    /* Asks user how they would like the sniffer to grab/store information */
    error = request_user_settings();
    if (error) {
        exit(1);
    }

    /* Set up a device to sniff packets */
    pcap_t *device_handle;
    error = create_sniffer(&device_handle);
    if (error) {
        exit(1);
    }

    /* 
    * Begin sniffing, if the user only wants to perform passive sniffing,
    * just print out however many packets they wanted
    */
    if (passive) { 
        pcap_loop(device_handle, packets_to_read, process_packet, NULL);
    } else { /*  If the user wants to perform active sniffing, enable ARP_Poisoning */
        
    }

    /* If the user opened a log file, close it */
    if (output_stream != stdout) {
        fclose(output_stream);
    }

    exit(1);
}
