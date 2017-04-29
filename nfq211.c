
//gcc ./nfq.c -o ./nfq  -lnetfilter_queue
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

#include "parser1.h"

#define PACK_LEN 65535

struct data_to_cb {
    //  int fd;
    struct namelist * pointer;
};
struct packet_dhcp_desc {
    int len;
    unsigned char packet[PACK_LEN];
};

int exchange_packet(struct nfq_data *tb, struct data_to_cb * data_for_analysis, struct  packet_dhcp_desc * dhcpd ) {

    struct sockaddr_ll socket_address;
    unsigned char * packet;
    struct namelist * pointer1;
    struct ifreq ifr1;
    int ret;

    pointer1 = data_for_analysis->pointer;

    ifr1.ifr_ifindex = nfq_get_indev(tb);

    if (pointer1 == NULL) {
        printf("No interfaces\n");
        return -4;
    }

    while (pointer1 != NULL) {
        //printf("pointer1->if_index %d\n", pointer1->if_index);
        if (ifr1.ifr_ifindex == pointer1->if_index ) break;
        if (pointer1->if_index != ifr1.ifr_ifindex && pointer1->next == NULL) return -5;
        pointer1 = pointer1->next;
    }

    ret = nfq_get_payload(tb, &packet);

    if (ret >= 0) {
        dhcpd->len = ret;
        struct iphdr *iph = (struct iphdr *)(packet);
        int iphdrlen = iph->ihl*4;
        struct udphdr *udph = (struct udphdr*)(packet + iphdrlen);
        udph->dest = htons(pointer1->port);
        udph->check = 0;
        memcpy(dhcpd->packet,packet,ret);
    }
    else {
        printf("packet is empty!");
        return -3;
    }
   
    return 1;

}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct packet_dhcp_desc dhcp_d;
    struct nfqnl_msg_packet_hdr *ph;
    memset(&dhcp_d,0,sizeof(dhcp_d));
    
    if (ph = nfq_get_msg_packet_hdr(nfa)) {
        id = ntohl(ph->packet_id);
    }
    int a;
    if ( (a=exchange_packet(nfa, data, &dhcp_d))<0) {
        // printf("exchange_packet %d\n",a );
        printf ("DHCP-proxy isn't configured on interface!\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL );
    }
    else return nfq_set_verdict(qh, id, NF_ACCEPT, dhcp_d.len,dhcp_d.packet );
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct data_to_cb data;
    int fd;
    int rv;
    char buf[PACK_LEN];

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

    int sock_dgramm = socket(AF_INET, SOCK_DGRAM, 0) ;
    if(sock_dgramm < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    struct namelist * root = NULL;
    int check = parse_config("dhcp-proxy.conf", &root, sock_dgramm);

    close(sock_dgramm);
    data.pointer = root;

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb,  &data);
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

    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        nfq_handle_packet(h, buf, rv);
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

