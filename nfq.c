
//gcc ./nfq.c -o ./nfq  -lnetfilter_queue -lpthread
//iptables -A INPUT -p udp --dport 67 -j NFQUEUE --queue-num 0

//# Выполняем проксирование для новых соединений
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#define BUF_SIZ	1024


int packet_socket ();
void print_udp_packet(unsigned char * , int );
void PrintData (unsigned char* , int );
void print_ip_header(unsigned char* , int );
void ProcessPacket(unsigned char*, int );
uint16_t udp4_checksum (struct ip , struct udphdr , uint8_t *payload, int payloadlen);
uint16_t checksum (uint16_t *, int);
struct ifreq if_mac;

int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;



void send_l2_packet(struct nfq_data *tb, int sockfd)
{
//Get the index of the interface to send on

    struct sockaddr_ll socket_address;
    unsigned char * data;
    char sendbuf[BUF_SIZ];
    struct ether_header *eh = (struct ether_header *) sendbuf;
    struct ifreq ifr;
    struct nfqnl_msg_packet_hw *hwph;
    int ret;

    memset( sendbuf, 0, BUF_SIZ);
    /* Construct the Ethernet header */

    /*  prepare L2  */
    ifr.ifr_ifindex = nfq_get_indev(tb);
    if (ioctl(sockfd, SIOCGIFNAME, &ifr) != -1)
        printf ("\nInterface name %s\n", ifr.ifr_name);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
        perror("SIOCGIFHWADDR");

    for (i=0 ; i<6; i++ )
        eh->ether_dhost[i] = ((uint8_t *)&ifr.ifr_hwaddr.sa_data)[i];

    for (i=0 ; i<6; i++ )
        eh->ether_shost[i] = ((uint8_t *)(nfq_get_packet_hw(tb)->hw_addr))[i];

    eh->ether_type = htons(ETH_P_IP);

    /*  prepare L3  */
    ret = nfq_get_payload(tb, &data);

    if (ret >= 0) {

        struct iphdr *iph = (struct iphdr *)(data);
        int iphdrlen = iph->ihl*4;
        struct udphdr *udph = (struct udphdr*)(data + iphdrlen);
        udph->dest = htons(10001);
        udph->check = 0;
        /*prepare all packet*/
        memcpy(sendbuf+sizeof(struct ether_header), data, ret);

        /* prepare sockaddr_ll   */
        socket_address.sll_family = AF_PACKET;
        socket_address.sll_protocol =  htons(ETH_P_IP) ;
        socket_address.sll_ifindex = nfq_get_indev(tb);
        socket_address.sll_halen = ETH_ALEN;

        for (i=0 ; i<6; i++ )
            socket_address.sll_addr[i] = eh->ether_dhost[i];

        /*send to dhcp */
        int result;
        if ( (result = sendto(sockfd, sendbuf, sizeof(struct ether_header)+ret, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll))) < 0)
            printf("Send failed\n");
        else printf("send to dhcp server = %d\n ", result);
    }
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{

    u_int32_t id;
    int fd;
    unsigned char * data1;
    int ret;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);


    fd = *((int*)data);
    send_l2_packet(nfa, fd);

    // printf("entering callback\n");

    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    int sock_raw = socket(PF_PACKET , SOCK_RAW , htons(ETH_P_IP)) ;
    printf("sock_raw number %d\n", sock_raw);
    if(sock_raw < 0) {
        printf("Socket Error\n");
        return 1;
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb,  &sock_raw);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }


    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }



    fd = nfq_fd(h);

    // para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)



    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        int b =nfq_handle_packet(h, buf, rv);
    }


    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}


void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;
    unsigned short udplen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen);
    struct dhcp_packet *dhcp = (struct dhcp_packet*)(Buffer + iphdrlen + 8);

    printf("\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udph->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    printf("\n");
    printf("IP Header\n");
    //  PrintData(Buffer , iphdrlen);

    printf("UDP Header\n");
    //  PrintData(Buffer+iphdrlen , sizeof udph);

    printf("Data Payload\n");
    //  PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));

    printf("\n###########################################################");

}






void PrintData (unsigned char* data , int Size)
{

    for(i=0 ; i < Size ; i++) {
        if( i!=0 && i%16==0) { //if one line of hex printing is complete...
            printf("\n\n         ");
            for(j=i-16 ; j<i ; j++) {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet

                else printf("."); //otherwise print a dot
            }
            printf("\n");
        }

        if(i%16==0) printf("   ");
        printf(" %02X",(unsigned int)data[i]);

        if( i==Size-1) { //print the last spaces
            for(j=0; j<15-i%16; j++) printf("   "); //extra spaces

            printf("         ");

            for(j=i-i%16 ; j<=i ; j++) {
                if(data[j]>=32 && data[j]<=128) printf("%c",(unsigned char)data[j]);
                else printf(".");
            }
            printf("\n");
        }
    }
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

    printf("\n");
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
    printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printf("   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    printf("   |-Identification    : %d\n",ntohs(iph->id));

    printf("   |-TTL      : %d\n",(unsigned int)iph->ttl);
    printf("   |-Protocol : %d\n",(unsigned int)iph->protocol);
    printf("   |-Checksum : %d\n",ntohs(iph->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void ProcessPacket(unsigned char* buffer, int size)
{
    //Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr*)buffer;
    ++total;

    switch (iph->protocol) { //Check the Protocol and do accordingly...
    case 1:  //ICMP Protocol
        ++icmp;
        //PrintIcmpPacket(Buffer,Size);
        break;

    case 2:  //IGMP Protocol
        ++igmp;
        break;

    case 6:  //TCP Protocol
        ++tcp;
        // print_tcp_packet(buffer , size);
        break;

    case 17: //UDP Protocol
        ++udp;
        printf("\nudp\n");
        print_udp_packet(buffer , size);
        break;

    default: //Some Other Protocol like ARP etc.
        printf("\nother\n");
        ++others;
        break;
    }
    printf("\nTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}


typedef unsigned short u16;
typedef unsigned long u32;





