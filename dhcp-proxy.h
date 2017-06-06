#ifndef DHCP_PROXY_INCLUDE__
#define DHCP_PROXY_INCLUDE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <net/if.h>
#include <pthread.h>


#define PACK_LEN 65535
#define LINUX_NAME_LEN 16
#define UDP_PORT 17
#define IP6HDRLEN 40
#define UDPHDRLEN 8
#define DEFAULT_PATH "/etc/dhcp-proxy.conf"
#define DHCP_4_SOURCE_PORT 67
#define DHCP_6_SOURCE_PORT 547

struct packet_dhcp_desc
{
    int len;
    unsigned char packet[PACK_LEN];
};

struct namelist
{
    int port ;
    char name[LINUX_NAME_LEN];
    int if_index;
    struct namelist * next;
};

struct namelist_analisys
{
    struct namelist * interf_list;
    int ip_ver ;
};

int exchange_packet(struct nfq_data *, struct namelist_analisys *, struct  packet_dhcp_desc *  );
uint16_t udp6_checksum (struct ip6_hdr , struct udphdr , uint8_t *, int );
uint16_t udp4_checksum (struct ip, struct udphdr , uint8_t *, int );
uint16_t checksum (uint16_t *, int );
int remove_namelist(struct namelist * );
void * thread_dhcp_proxy6(void* );
void * thread_dhcp_proxy(void* );
#endif
