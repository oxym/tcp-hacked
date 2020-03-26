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
#define PAYLOAD "Hello, I'm Eve!"

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
    int sockfd, n, yes = 1;
    char datagram[DATAGRAMSIZE], pseudo_packet[PSEUDOPACKETSIZE], ipstr[INET_ADDRSTRLEN];;
    char *pseudo_ptr = &pseudo_packet;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct pshdr *psh;
    char *srcIP = "10.0.2.15";
    char *svrIP = "172.19.3.82";
    uint16_t srcPort = 35801;
    uint16_t svrPort = 35801;
    uint32_t seq0 = 2220844409;
    uint16_t id0 = 39326;
    uint16_t window_size = 29200;
    size_t tcp_len;
    void *data;
    struct sockaddr_in sa;

    // Open raw socket without protocol header
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("fakesync: socket");
        exit(-1);
    }

    // Set option to include protocol header
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof yes) <0) {
        perror("fakesync: socketopt()");
        exit(-1);
    }

    // build sockaddr
    sa.sin_family = AF_INET;
    sa.sin_port = htons(svrPort);
    inet_pton(AF_INET, svrIP, &(sa.sin_addr.s_addr));

    // carve out IP header and TCP header
    memset(datagram, 0, sizeof datagram);
    iph = (struct iphdr *) datagram;
    tcph = (struct tcphdr *) (iph + sizeof(struct iphdr));
    data = (char *) (tcph + sizeof(struct tcphdr));
    strcpy(data, PAYLOAD);

    tcp_len = sizeof(struct tcphdr) + strlen(data);

    // pack IP header
    iph -> version = 4; // IPv4
    iph -> ihl = 5; // 5 * 32 bits
    iph -> tos = 0; // DSCP: default; ECN: Not ECN-capable transport
    iph -> tot_len = htons(sizeof(struct iphdr) + tcp_len); // total length
    printf("ip: tot_len: %d\n", sizeof(struct iphdr) + tcp_len);
    iph -> id = htons(id0); // start ID
    iph -> frag_off = 0x00;
    iph -> ttl = 64; // time to live
    iph -> protocol = IPPROTO_TCP; // TCP
    iph -> check = 0;
    inet_pton(AF_INET, srcIP, &(iph -> saddr));
    inet_pton(AF_INET, svrIP, &(iph -> daddr));
    inet_ntop(AF_INET, &(iph -> saddr), ipstr, INET_ADDRSTRLEN);
    printf("ip: source: %s\n", ipstr);
    inet_ntop(AF_INET, &(iph -> daddr), ipstr, INET_ADDRSTRLEN);
    printf("ip: destination: %s\n", ipstr);


    // calculate IP check sum
    iph -> check = ip_checksum((void *) datagram, sizeof(struct iphdr) + tcp_len);
    
    // pack TCP header
    tcph -> source = htons(srcPort); //16 bit in nbp format of source port
    tcph -> dest = htons(svrPort); //16 bit in nbp format of destination port
    tcph -> seq = htonl(seq0++); //32 bit sequence number, initially set to zero
    tcph -> ack_seq = 0x0; //32 bit ack sequence number, depends whether ACK is set or not
    tcph -> res1 = 0; //4 bits: Not used
    tcph -> res2 = 0; //4 bits: Not used
    tcph -> doff = 5; //4 bits: 5 x 32-bit words on tcp header
    // tcph -> cwr = 0; //Congestion control mechanism
    // tcph -> ece = 0; //Congestion control mechanism
    tcph -> urg = 0; //Urgent flag
    tcph -> ack = 0; //Acknownledge
    tcph -> psh = 0; //Push data immediately
    tcph -> rst = 0; //RST flag
    tcph -> syn = 1; //SYN flag
    tcph -> fin = 0; //Terminates the connection
    tcph -> window = htons(window_size);//0xFFFF; //16 bit max number of databytes
    tcph -> check = 0; //16 bit check sum. Can't calculate at this point
    tcph -> urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set
    
    // construct psudo packet
    memset(pseudo_packet, 0, sizeof pseudo_packet);
    psh = (struct pshdr *) pseudo_packet;
    memcpy(pseudo_ptr + sizeof(struct pshdr), (char *)tcph, tcp_len);

    // pack pseudo header
    inet_pton(AF_INET, srcIP, &(psh -> src_addr)); // 32 bit source address
    inet_pton(AF_INET, svrIP, &(psh -> dst_addr)); // 32 bit destination address
    inet_ntop(AF_INET, &(psh -> src_addr), ipstr, INET_ADDRSTRLEN);
    printf("pseudo: source: %s\n", ipstr);
    inet_ntop(AF_INET, &(psh -> dst_addr), ipstr, INET_ADDRSTRLEN);
    printf("pseudo: destination: %s\n", ipstr);

    psh -> reserved = 0;
    psh -> protocol = IPPROTO_TCP; // TCP
    psh -> tcp_len = htons(tcp_len); // TCP segment length

    tcph -> check = ip_checksum(pseudo_ptr, sizeof(struct pshdr) + tcp_len);

    if ((n = sendto(sockfd, datagram, sizeof(struct iphdr) + tcp_len, 0, (struct sockaddr *) &sa, sizeof sa)) < 0)
    {
        perror("fakesync: sendto()");
    }
    else
    {
        printf("sent %d bytes.\n", n);
    }

    return 0;
}