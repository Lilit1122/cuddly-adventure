#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
       #include <net/if.h>

void print_udp_packet(unsigned char * , int );
void PrintData (unsigned char* , int );
void print_ip_header(unsigned char* , int );
void ProcessPacket(unsigned char* , int );


struct interface {
  int index;
  struct in_addr addr; //
  struct interface *next; //оказатель на новую структуру, однонаправленный список.
};

struct dhcp_packet_with_opts{  
  struct dhcp_packet {
    unsigned char op, htype, hlen, hops;
    unsigned int xid;
    unsigned short secs, flags;
    struct in_addr ciaddr, yiaddr, siaddr, giaddr;
    unsigned char  sname[64], file[128];
  } header;
  unsigned char options[312];
};




struct interface *ifaces = NULL;
int iface_index;
int sock_raw;
FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j,oneopt=1,mtuopt = IP_PMTUDISC_DONT;
struct sockaddr_in source,dest;
 
int main()
{
struct ifreq ifr;    
    //size_t buf_size = sizeof(struct dhcp_packet_with_opts);
    int saddr_size , data_size;
    struct sockaddr saddr;
    struct in_addr in;
     
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    
    
    printf("Starting...\n");
    //Create a raw socket that shall sniff
    sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);
     if(sock_raw < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    if (setsockopt(sock_raw, SOL_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||   //Возвращение  дополнительной информации об интерфейсе
      setsockopt(sock_raw, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1 ||  //Получение броадкастовых сообщений
      setsockopt(sock_raw, SOL_IP, IP_MTU_DISCOVER, &mtuopt, sizeof(mtuopt)) == -1)  //Убирает флаг "не фрагментировать"
    {
      perror("dhcp-proxy: cannot set options on DHCP socket");
      exit(1);
    }

    while(1)
    {
  
    struct msghdr msg; // Структура, которую возвращает recvmasg
    struct iovec iov;  // Структура, которую возвращает recvmasg
    struct cmsghdr *cmptr;  //Для создания управляющих сообщений
    struct in_pktinfo *pkt; //
    union {
      struct cmsghdr align; /* this ensures alignment */
      char control[CMSG_SPACE(sizeof(struct in_pktinfo))];  //
    } control_u;
        
    msg.msg_control = control_u.control; //
    msg.msg_controllen = sizeof(control_u); //
    msg.msg_name = &saddr;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    iov.iov_base = buffer;
    iov.iov_len = 65536;
    int sz;

    while ((sz = recvmsg(sock_raw, &msg, 0)) == -1 && errno == EINTR); //выход будет, когда мы примем сообщение без ошибки, или с ошибкой не равной EINTR
   // printf ("sz = %d",sz);
    
   iface_index = 0;
   for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr)) 
    if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO)  // Если вот эти 2 поля установлены в соответствующие значеия, дополнительная инфа передается с пакетом
	  {
         
          union {    //создаем объединение
            unsigned char *c;  //указатель на какой символ 
            struct in_pktinfo *p;  //указатель на структуру со вспомогательной инфой о пакете 
          } p;
          p.c = CMSG_DATA(cmptr);  // присвоили указатель на эту структуру  в поле с структуры p
          iface_index = p.p->ipi_ifindex; // получили индекс интерфейса с которого пришел пакет
	  }
       
      // printf ("iface_index %d",iface_index);
       ifr.ifr_ifindex = iface_index;
   if  (ioctl(sock_raw, SIOCGIFNAME, &ifr) != -1) printf ("\nInterface name %s\n", ifr.ifr_name); 
    
       
        ProcessPacket(buffer, data_size);
    }
    close(sock_raw);
    printf("Finished");
    return 0;
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
    PrintData(Buffer , iphdrlen);
         
    printf("UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
         
    printf("Data Payload\n");  
    PrintData(Buffer + iphdrlen + sizeof udph ,( Size - sizeof udph - iph->ihl * 4 ));
     
    printf("\n###########################################################");
    
}

void PrintData (unsigned char* data , int Size)
{
     
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            printf("         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else printf("."); //otherwise print a dot
            }
            printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) printf("   "); //extra spaces
             
            printf("         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
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
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
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
            print_udp_packet(buffer , size);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    printf("\nTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r",tcp,udp,icmp,igmp,others,total);
}


 
