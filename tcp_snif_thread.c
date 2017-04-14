//(15:14:30) alexander.guly@jabber.eltex.loc: Минимально - добавить в потоки соккет и слушать его, если пришла инфа - проверить //тебе ли она (по сути всё тоже самое, только расход ресурсов больше)


#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //memset
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<sys/socket.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t

#define __FAVOR_BSD           // Use BSD format of tcp header
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <pthread.h>
#include <unistd.h>


#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes options data
#define MD5_DIGEST_LEN 16
#define SOURCE_IP "11.11.11.8"
#define INT_NAME "lo"
#define BIND_IP "127.0.0.1"
#define TCPPORT 10000
#define FILENAMELEN 20

struct packet_finish
{
    uint8_t *packet;
    int packet_len;
    char *src_ip;
    char *payload;
    int *ip_flags;
    int * tcp_flags;
};

struct ThreadArgs
{
    int FD1; // Socket descriptor for client
    int FD2;
    int FD3;
    char * filename ;
    int filename_len;
};

struct ThreadArgsFirst
{
    int FD3;
    int sock_raw1;
};



void ProcessPacket(unsigned char* , int);
int print_tcp_packet(unsigned char* , int, struct sockaddr_in *);
void PrintData (unsigned char* , int);
uint16_t checksum (uint16_t *, int);
uint16_t tcp4_checksum (struct ip, struct tcphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);
int packet_compiling (char *, int, struct sockaddr_in *,struct packet_finish *);
int prepare_second_layer(struct ifreq *);
int print_file_checksumm(unsigned char* , int , struct sockaddr_in * );
void *ThreadMain(void *arg );
void *ThreadFrst(void *threadArgs);

int sock_raw1, sd;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;




int main(int argc, char **argv)
{
    const int on = 1;
    int data_size, m,sd;
    struct sockaddr_in serv_addr;
    struct sockaddr_in recaddr;
    struct ifreq ifr;

    if (argc < 2)
    {
        fprintf(stderr,"usage: %s <send_file_name>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
    // For that, we need to specify a destination for the kernel in order for it
    // to decide where to send the raw datagram. We fill in a struct in_addr with
    // the desired destination IP address, and pass this structure to the sendto() function.
    memset (&recaddr, 0, sizeof (struct sockaddr_in));
    recaddr.sin_family = AF_INET;

    //Create a raw socket that shall sniff
    sock_raw1 = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    memset((char *) &serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
//    serv_addr.sin_addr.s_addr = INADDR_ANY;


    inet_pton(AF_INET, BIND_IP, &(serv_addr.sin_addr.s_addr));
    serv_addr.sin_port = TCPPORT;
    if (bind(sock_raw1, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("bind() failed: ");
        return EXIT_FAILURE;
    }
    if(sock_raw1 < 0)
    {
        printf("Socket Error\n");
        return 1;
    }

    prepare_second_layer(&ifr);


// Submit request for a raw socket descriptor.
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0)
    {
        perror ("setsockopt() failed to set IP_HDRINCL ");
        exit (EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0)
    {
        perror ("setsockopt() failed to bind to interface ");
        exit (EXIT_FAILURE);

    }



    int pipe1[2], pipe3[2],i;

    int * pipe2[argc-1];

    for (i = 0; i < argc-1; i++)
    {
        pipe2[i] = (int *)malloc(2*sizeof(int));
        pipe(pipe2[i]+i);
        printf("pipe[%d][0]=%d,pipe[%d][1]=%d\n",i,pipe2[i][0],i,pipe2[i][1]);
    }

    pipe(pipe1);
    pipe(pipe3);
    printf("pipe3[0]=%d,pipe3[1]=%d\n",pipe3[0],pipe3[1]);

    struct ThreadArgs* threadArgs[argc];
    struct ThreadArgsFirst* ThreadFrst1struct;
    pthread_t * threadID[argc-1], thread1;

    for (i=0; i<argc-1; i++)
    {

        threadArgs[i]=(struct ThreadArgs*)malloc(sizeof(struct ThreadArgs));

        threadArgs[i]->FD1 = pipe1[0]; // Socket descriptor for client
        threadArgs[i]->FD2 = pipe2[i][0];
        threadArgs[i]->FD3 = pipe3[1];
        threadArgs[i]->filename = argv[i];
        threadArgs[i]->filename_len = strlen(argv[i]);
        int returnValue = pthread_create(threadID[i], NULL, ThreadMain, threadArgs[i]);
        if (returnValue != 0) printf("pthread_create() failed");
        printf("\n\n");
    }

    ThreadFrst1struct=(struct ThreadArgsFirst*)malloc(sizeof(struct ThreadArgsFirst));
    ThreadFrst1struct->FD3 = pipe3[0];
    ThreadFrst1struct->sock_raw1 = sd;

    int   returnValue = pthread_create(&thread1, NULL, ThreadFrst , ThreadFrst1struct);
    if (returnValue != 0) printf("pthread_create() failed");
    char filename[20];
    while(1)
    {
        unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
        memset (buffer, 0, 65536);
        data_size = recv(sock_raw1 , buffer , 65536 , 0);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets, pampam\n");
            return 1;
        }
        struct iphdr *iph = (struct iphdr*)buffer;
        struct tcphdr *tcph=(struct tcphdr*)(buffer + iph->ihl*4);

        if (tcph->th_sport == htons(TCPPORT) && tcph->th_dport == htons(TCPPORT)   )
        {

            if  (data_size - tcph->doff*4-iph->ihl*4 == 4)
            {
                m=print_tcp_packet(buffer , data_size, &recaddr);

                if (m == 1) write (pipe1[1], &recaddr , sizeof(struct sockaddr_in ));
            }
            else if  (data_size - tcph->doff*4-iph->ihl*4 == 36)
            {
                memcpy(filename, buffer + iph->ihl*4 + tcph->doff*4+MD5_DIGEST_LEN , 20);
                for (i=0; i<argc; i++)
                {
                    if (strcmp(filename, argv[i])==0) write (pipe2[i][1], buffer, data_size);
                }
            }
        }
    }
}

void *ThreadMain(void *threadArgs)
{
    pthread_detach(pthread_self());
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    memset (buffer, 0, 65536);
    int retval;
    struct timeval tv;
    struct packet_finish packet;
    struct sockaddr_in * recaddr;

    recaddr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in ));
    memset (recaddr, 0, sizeof(struct sockaddr_in ) );

    while(1)
    {

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(((struct ThreadArgs *)threadArgs)->FD1, &rfds);

        //tv.tv_sec = 0;
        //tv.tv_usec = 0;

        retval = select( ((struct ThreadArgs *)threadArgs)->FD1 + 1, &rfds, NULL, NULL, NULL);

        if (retval > 0)
        {


            int m = read(((struct ThreadArgs *)threadArgs)->FD1, recaddr, sizeof(struct sockaddr_in ));
            printf("Read: %d\n", m);

            int n =  packet_compiling( ((struct ThreadArgs *)threadArgs)->filename, ((struct ThreadArgs *)threadArgs)->filename_len, recaddr, &packet);

            printf ("\npacket.packet_len %d\n",packet.packet_len);


            int mn = write(((struct ThreadArgs *)threadArgs)->FD3, packet.packet, packet.packet_len );
            printf("Write %d byte\n", mn);
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(((struct ThreadArgs *)threadArgs)->FD2, &rfds);

            retval = select( ((struct ThreadArgs *)threadArgs)->FD2 + 1, &rfds, NULL, NULL, NULL);

            if (retval>0)
            {
                read(((struct ThreadArgs *)threadArgs)->FD2, buffer, 65536);
                print_file_checksumm(buffer, sizeof(buffer),  recaddr);

                free (threadArgs);
                free (packet.packet);
                free (packet.src_ip);
                free (packet.ip_flags);
                free (packet.tcp_flags);
                free (packet.payload);
            }
        }
    }
    free(buffer);
    //Free allocated memory.
    return (NULL);
}

void *ThreadFrst(void *threadArgs)
{
    pthread_detach(pthread_self());
    unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!
    memset (buffer, 0, 65536);
    int retval;
    struct timeval tv;

    while(1)
    {


        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(((struct ThreadArgsFirst *)threadArgs)->FD3, &rfds);


        printf("first stread descriptor %d",((struct ThreadArgsFirst *)threadArgs)->FD3);
        retval = select( ((struct ThreadArgsFirst *)threadArgs)->FD3 + 1, &rfds, NULL , NULL, NULL);

        if (retval > 0)
        {
            printf("Tada!!");
            int m = read (((struct ThreadArgs *)threadArgs)->FD3, buffer,100); //работает до сюда))
            printf("M bytes read: %d\n", m);
            /*/ Send packet.
              if (send (((struct ThreadArgsFirst *)threadArgs)->sock_raw1, buffer, 100, 0) < 0)
               {
               perror ("send() failed ");
               exit (EXIT_FAILURE);
               }
             */
            memset (buffer, 0, 100);
        }
    }
    //free(buffer);
}


int print_file_checksumm(unsigned char* Buffer, int Size, struct sockaddr_in * recaddr)
{

    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    // char *some_addr;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
    unsigned char data[MD5_DIGEST_LEN];
    char filename[20];


    memcpy(data, Buffer + iphdrlen + tcph->doff*4 , MD5_DIGEST_LEN);
    memcpy(filename, Buffer + iphdrlen + tcph->doff*4+MD5_DIGEST_LEN , 20);

    // printf("packet sizeof: %d\n", Size - tcph->doff*4-iph->ihl*4 )  ;

    printf("Checksumm:\n");
    //Size - tcph->doff*4-iph->ihl*4
    int i;
    for( i=0; i <MD5_DIGEST_LEN; i++)
    {
        printf("%02x",data[i]);
    }

    printf("\nfilename: %s\n", filename);
    //  PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
    recaddr->sin_addr.s_addr = iph->saddr;
    //some_addr=inet_ntoa(recaddr->sin_addr);
    //printf("\nclient_address %s\n", some_addr);

    return 1;
}



int print_tcp_packet(unsigned char* Buffer , int Size, struct sockaddr_in * recaddr)
{

    unsigned short iphdrlen;
    char key[5],sample[5] = "data\0";
    struct iphdr *iph = (struct iphdr *)Buffer;
    iphdrlen = iph->ihl*4;
    char *some_addr;
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);

    PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
    if (Size - tcph->doff*4-iph->ihl*4==4)
    {
        memcpy(key, Buffer + iphdrlen + tcph->doff*4 , 4);
        key[4]='\0';
        {

            recaddr->sin_addr.s_addr = iph->saddr;
            some_addr=inet_ntoa(recaddr->sin_addr);
            printf ("Connection request from %s \n", some_addr);
            return 1;
        }
    }
    else printf ("Fail!!!! ");


    return 0;
}

void PrintData (unsigned char* data , int Size)
{
    printf ("Data payload: \n");
    for(i=0 ; i < Size ; i++)
    {
        if(data[i]>=32 && data[i]<=128)
            printf("%c",(unsigned char)data[i]); //if its a number or alphabet

        else printf("."); //otherwise print a dot
        if (i%16==15 && i!=0) printf ("\n");
    }
    printf ("\n\n");
}

int prepare_second_layer(struct ifreq * ifr)
{

    char *interface;

    int sd;

    interface = allocate_strmem (40);
// Interface to send packet through.
    strcpy (interface, INT_NAME );

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
    {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    // Use ioctl() to look up interface index which we will use to
    // bind socket descriptor sd to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    memset (ifr, 0, sizeof (*ifr));
    snprintf (ifr->ifr_name, sizeof (ifr->ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFINDEX, ifr) < 0)
    {
        perror ("ioctl() failed to find interface ");

    }
    close (sd);
    printf ("Index for interface %s is %i\n", interface, ifr->ifr_ifindex);
    free (interface);
    return 1;
}



// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1)
    {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0)
    {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr, uint8_t *payload, int payloadlen)
{
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int i, chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
    ptr += sizeof (iphdr.ip_src.s_addr);
    chksumlen += sizeof (iphdr.ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
    ptr += sizeof (iphdr.ip_dst.s_addr);
    chksumlen += sizeof (iphdr.ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0;
    ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
    ptr += sizeof (iphdr.ip_p);
    chksumlen += sizeof (iphdr.ip_p);

    // Copy TCP length to buf (16 bits)
    svalue = htons (sizeof (tcphdr) + payloadlen);
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
    ptr += sizeof (tcphdr.th_sport);
    chksumlen += sizeof (tcphdr.th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
    ptr += sizeof (tcphdr.th_dport);
    chksumlen += sizeof (tcphdr.th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
    ptr += sizeof (tcphdr.th_seq);
    chksumlen += sizeof (tcphdr.th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
    ptr += sizeof (tcphdr.th_ack);
    chksumlen += sizeof (tcphdr.th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
    ptr += sizeof (tcphdr.th_flags);
    chksumlen += sizeof (tcphdr.th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
    ptr += sizeof (tcphdr.th_win);
    chksumlen += sizeof (tcphdr.th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
    ptr += sizeof (tcphdr.th_urp);
    chksumlen += sizeof (tcphdr.th_urp);

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
    void *tmp;

    if (len <= 0)
    {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL)
    {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    }
    else
    {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
    void *tmp;

    if (len <= 0)
    {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL)
    {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    }
    else
    {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int *
allocate_intmem (int len)
{
    void *tmp;

    if (len <= 0)
    {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (int *) malloc (len * sizeof (int));
    if (tmp != NULL)
    {
        memset (tmp, 0, len * sizeof (int));
        return (tmp);
    }
    else
    {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit (EXIT_FAILURE);
    }
}

int packet_compiling (char * text, int textlen, struct sockaddr_in *dst_ip, struct packet_finish * packet1)
{
    int i, status,  *ip_flags, *tcp_flags;
    char *src_ip;
    struct ip iphdr;
    struct tcphdr tcphdr;
    char *payload;
    int payloadlen;
    uint8_t *packet;

    // Allocate memory for various arrays.
    packet = allocate_ustrmem (IP_MAXPACKET);

    src_ip = allocate_strmem (INET_ADDRSTRLEN);
    ip_flags = allocate_intmem (4);
    tcp_flags = allocate_intmem (8);
    payload = allocate_strmem (IP_MAXPACKET);


    packet1->packet = packet;
    packet1->src_ip = src_ip;
    packet1->ip_flags = ip_flags;
    packet1->tcp_flags = tcp_flags;
    packet1->payload = payload;


    // Set TCP data.

    memcpy (payload, text, textlen);
    printf ("%s", payload);
    payloadlen = textlen;


    // Source IPv4 address: you need to fill this out
    strcpy (src_ip, SOURCE_IP);


    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;

    // Type of service (8 bits)
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + TCP header + TCP data
    iphdr.ip_len = htons (IP4_HDRLEN + TCP_HDRLEN + payloadlen);

    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = htons (0);

    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

    // Zero (1 bit)
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 1;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons ((ip_flags[0] << 15)
                          + (ip_flags[1] << 14)
                          + (ip_flags[2] << 13)
                          +  ip_flags[3]);

    // Time-to-Live (8 bits): default to maximum value
    iphdr.ip_ttl = 255;

    // Transport layer protocol (8 bits): 6 for TCP
    iphdr.ip_p = IPPROTO_TCP;

    // Source IPv4 address (32 bits)



    if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1)
    {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    iphdr.ip_dst = dst_ip->sin_addr;

    // Destination IPv4 address (32 bits)
//  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
//    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
//    exit (EXIT_FAILURE);
//  }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr.ip_sum = 0;
    iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    // TCP header

    // Source port number (16 bits)
    tcphdr.th_sport = htons (TCPPORT);

    // Destination port number (16 bits)
    tcphdr.th_dport = htons (TCPPORT);

    // Sequence number (32 bits)
    tcphdr.th_seq = htonl (0);

    // Acknowledgement number (32 bits)
    tcphdr.th_ack = htonl (0);

    // Reserved (4 bits): should be 0
    tcphdr.th_x2 = 0;

    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr.th_off = TCP_HDRLEN / 4;

    // Flags (8 bits)

    // FIN flag (1 bit)
    tcp_flags[0] = 0;

    // SYN flag (1 bit)
    tcp_flags[1] = 0;

    // RST flag (1 bit)
    tcp_flags[2] = 0;

    // PSH flag (1 bit)
    tcp_flags[3] = 1;

    // ACK flag (1 bit)
    tcp_flags[4] = 1;

    // URG flag (1 bit)
    tcp_flags[5] = 0;

    // ECE flag (1 bit)
    tcp_flags[6] = 0;

    // CWR flag (1 bit)
    tcp_flags[7] = 0;

    tcphdr.th_flags = 0;
    for (i=0; i<8; i++)
    {
        tcphdr.th_flags += (tcp_flags[i] << i);
    }

    // Window size (16 bits)
    tcphdr.th_win = htons (65535);

    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr.th_urp = htons (0);

    // TCP checksum (16 bits)
    tcphdr.th_sum = tcp4_checksum (iphdr, tcphdr, (uint8_t *) payload, payloadlen);

    // Prepare packet.

    // First part is an IPv4 header.
    memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));

    // Next part of packet is upper layer protocol header.
    memcpy ((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN * sizeof (uint8_t));

    // Last part is upper layer protocol data.
    memcpy ((packet + IP4_HDRLEN + TCP_HDRLEN), payload, payloadlen * sizeof (uint8_t));


    packet1->packet_len = IP4_HDRLEN + TCP_HDRLEN + payloadlen;

    return 1;

}


