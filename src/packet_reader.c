#include "packet_reader.h"

int tcp = 0, udp = 0, icmp = 0, igmp = 0, ip = 0, others = 0, total = 0;

void process_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
	int size = header->len;
     
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1: //ICMP Protocol
            ++icmp;
            print_icmp_packet(packet, size);
            break;

        case 2: //IGMP Protocol
            ++igmp;
            break;
         
        case 6: //TCP Protocol
            ++tcp;
            print_tcp_packet(packet, size);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(packet, size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    
    printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp, others, total);
}

void print_ethernet_header(const u_char *packet, int size) {
	struct ethhdr *eth = (struct ethhdr *)packet;
     
    fprintf(output_stream, "\n");
    fprintf(output_stream, "Ethernet Header\n");
    fprintf(output_stream, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(output_stream, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(output_stream, "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char *packet, int size) {
	print_ethernet_header(packet, size);
	print_ethernet_header(packet, size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(output_stream, "\n");
    fprintf(output_stream, "IP Header\n");
    fprintf(output_stream, "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(output_stream, "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(output_stream, "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(output_stream, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(output_stream, "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(output_stream, "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(output_stream, "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(output_stream, "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(output_stream, "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(output_stream, "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(output_stream, "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(output_stream, "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(output_stream, "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}

void print_tcp_packet(const u_char *packet, int size) {
	unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( packet  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
    fprintf(output_stream, "\n\n***********************TCP Packet*************************\n");  
         
    print_ip_header(packet, size);
         
    fprintf(output_stream, "\n");
    fprintf(output_stream, "TCP Header\n");
    fprintf(output_stream, "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(output_stream, "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(output_stream, "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(output_stream, "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(output_stream, "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(output_stream, "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(output_stream, "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(output_stream, "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(output_stream, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(output_stream, "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(output_stream, "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(output_stream, "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(output_stream, "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(output_stream, "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(output_stream, "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(output_stream, "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(output_stream, "\n");
    fprintf(output_stream, "                        DATA Dump                         ");
    fprintf(output_stream, "\n");
         
    fprintf(output_stream, "IP Header\n");
    print_data(packet,iphdrlen);
         
    fprintf(output_stream, "TCP Header\n");
    print_data(packet+iphdrlen,tcph->doff*4);
         
    fprintf(output_stream, "Data Payload\n");    
    print_data(packet + header_size , size - header_size );
                         
    fprintf(output_stream, "\n###########################################################");
}

void print_udp_packet(const u_char *packet, int size) {
	unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(packet +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(packet + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
    fprintf(output_stream, "\n\n***********************UDP Packet*************************\n");
     
    print_ip_header(packet , size);           
     
    fprintf(output_stream, "\nUDP Header\n");
    fprintf(output_stream, "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(output_stream, "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(output_stream, "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(output_stream, "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(output_stream, "\n");
    fprintf(output_stream, "IP Header\n");
    print_data(packet , iphdrlen);
         
    fprintf(output_stream, "UDP Header\n");
    print_data(packet+iphdrlen , sizeof udph);
         
    fprintf(output_stream, "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    print_data(packet + header_size , size - header_size);
     
    fprintf(output_stream, "\n###########################################################");
}

void print_icmp_packet(const u_char *packet, int size) {
	unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(packet  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(packet + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
    fprintf(output_stream, "\n\n***********************ICMP Packet*************************\n"); 
     
    print_ip_header(packet , size);
             
    fprintf(output_stream, "\n");
         
    fprintf(output_stream, "ICMP Header\n");
    fprintf(output_stream, "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(output_stream, "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(output_stream, "  (ICMP Echo Reply)\n");
    }
     
    fprintf(output_stream, "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(output_stream, "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(output_stream, "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(output_stream, "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(output_stream, "\n");
 
    fprintf(output_stream, "IP Header\n");
    print_data(packet,iphdrlen);
         
    fprintf(output_stream, "UDP Header\n");
    print_data(packet + iphdrlen , sizeof icmph);
         
    fprintf(output_stream, "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    print_data(packet + header_size , (size - header_size) );
     
    fprintf(output_stream, "\n###########################################################");
}

void print_data (const u_char *data, int size) {
	int i , j;
    for(i=0 ; i < size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(output_stream, "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(output_stream, "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(output_stream, "."); //otherwise print a dot
            }
            fprintf(output_stream, "\n");
        } 
         
        if(i%16==0) fprintf(output_stream, "   ");
            fprintf(output_stream, " %02X",(unsigned int)data[i]);
                 
        if( i==size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(output_stream, "   "); //extra spaces
            }
             
            fprintf(output_stream, "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(output_stream, "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(output_stream, ".");
                }
            }
             
            fprintf(output_stream,  "\n" );
        }
    }
}
