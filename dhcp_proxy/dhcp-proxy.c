//iptables -A INPUT -p udp --dport 67 -j NFQUEUE --queue-num 4
#include "dhcp-proxy.h"
#include "parser.h"

int exchange_packet(struct nfq_data *tb, struct namelist_analisys * data_for_analysis, struct  packet_dhcp_desc * dhcpd )
{

    unsigned char * packet;
    struct namelist * ptr;
    int indev = nfq_get_indev(tb);
    int ret;
    int iphdrlen;

    if (data_for_analysis->ip_ver==4)
    {

        ptr = data_for_analysis->interf_list;

        if (ptr == NULL)
        {
            syslog(LOG_ERR, "No interfaces!");
            return (-1);
        }

        while (ptr != NULL)
        {
            if (indev == ptr->if_index ) break;
            if (ptr->if_index != indev && ptr->next == NULL) return (-1);
            ptr = ptr->next;
        }

        ret = nfq_get_payload(tb, &packet);

        if (ret >= 0)
        {
            dhcpd->len = ret;
            struct iphdr *iph = (struct iphdr *)(packet);
            iphdrlen = iph->ihl*4;
            if (iph->protocol != UDP_PORT)
            {
                syslog(LOG_ERR,"Recieved packet is not UDP!!!");
                return (-1);
            }
            struct udphdr *udph = (struct udphdr*)(packet + iphdrlen);
            udph->dest = htons(ptr->port);
            udph->source = htons(DHCP_6_SOURCE_PORT);
            udph->check = 0;
            memcpy(dhcpd->packet,packet,ret);

        }
        else
        {
            syslog(LOG_ERR, "Packet is empty!");
            return (-1);
        }
    }
    else if (data_for_analysis->ip_ver==6)
    {

        ptr = data_for_analysis->interf_list;

        indev = nfq_get_indev(tb);

        if (ptr == NULL)
        {
            syslog(LOG_ERR,"No interfaces");
            return (-1);
        }

        while (ptr != NULL)
        {

            if (indev == ptr->if_index )	break;
            if (ptr->if_index != indev && ptr->next == NULL) return (-1);
            ptr = ptr->next;

        }

        ret = nfq_get_payload(tb, &packet);

        if (ret > 0)
        {

            dhcpd->len = ret;
            struct ip6_hdr * iphdr = (struct ip6_hdr *)(packet);
            if (iphdr->ip6_nxt != UDP_PORT)
            {
                syslog(LOG_ERR,"Recieved packet is not UDP!!!");
                return (-1);
            }
            struct udphdr *udph = (struct udphdr*)(packet + IP6HDRLEN);
            udph->dest = htons(ptr->port);
            udph->source = htons(DHCP_6_SOURCE_PORT);
            udph->check = htons(0);
            udph->check = udp6_checksum (*iphdr, *udph, ( uint8_t *)udph+UDPHDRLEN,  (int) udph->len );
            memcpy(dhcpd->packet,packet,ret);
        }
        else
        {
            syslog(LOG_ERR,"packet is empty!");
            return (-1);
        }
    }
    else
    {
        syslog(LOG_ERR,"wrong config!");
        return (-1);
    }
    return(0);
}

//________________________________________________________________

int exchange_packet_for_client(struct nfq_data *tb, int * vershion, struct  packet_dhcp_desc * dhcpd )
{

    unsigned char * packet;
    int ret;
    int iphdrlen;

    ret = nfq_get_payload(tb, &packet);
    if (ret <= 0){
        syslog(LOG_ERR,"packet is empty!");
        return (-1);
    }
    dhcpd->len = ret;

    if (*vershion==4) {

        struct iphdr *iph = (struct iphdr *)(packet);
        iphdrlen = iph->ihl*4;
        if (iph->protocol != UDP_PORT)
        {
            syslog(LOG_ERR,"Recieved packet is not UDP!!!");
            return (-1);
        }
        struct udphdr *udph = (struct udphdr*)(packet + iphdrlen);
        udph->source = htons(DHCP_4_SOURCE_PORT);
        udph->check = 0;
        memcpy(dhcpd->packet,packet,ret);
        syslog(LOG_DEBUG,"Packet source port has been exhanged DHCP_4_SOURCE_PORT");
    }

    else if  (*vershion==6) {

        struct ip6_hdr * iphdr = (struct ip6_hdr *)(packet);
        if (iphdr->ip6_nxt != UDP_PORT)
        {
            syslog(LOG_ERR,"Recieved packet is not UDP!!!");
            return (-1);
        }
        struct udphdr *udph = (struct udphdr*)(packet + IP6HDRLEN);
        udph->source = htons(DHCP_6_SOURCE_PORT);
        udph->check = 0;
        udph->check = udp6_checksum (*iphdr, *udph, ( uint8_t *)udph+UDPHDRLEN,  (int) udph->len );
        memcpy(dhcpd->packet,packet,ret);
        syslog(LOG_DEBUG,"Packet source port has been exhanged DHCP_6_SOURCE_PORT");
        }
    else
        {
        syslog(LOG_ERR,"wrong config!");
        return (-1);
        }

    return(0);
}


//________________________________________________________________



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    struct packet_dhcp_desc dhcp_d;
    struct nfqnl_msg_packet_hdr *ph;
    memset(&dhcp_d,0,sizeof(dhcp_d));

    if ((ph = nfq_get_msg_packet_hdr(nfa)))
    {
        id = ntohl(ph->packet_id);
    }

    if ((exchange_packet(nfa, data, &dhcp_d))<0)
    {
        syslog(LOG_ERR,"DHCP-proxy isn't configured on interface!");
        return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL ));
    }
    else
    {
        syslog(LOG_DEBUG,"Packet dhcpv %d has sent to port %d", ((struct namelist_analisys *) data) -> ip_ver ,((struct namelist_analisys *) data) -> interf_list -> port);
        return (nfq_set_verdict(qh, id, NF_ACCEPT, dhcp_d.len,dhcp_d.packet ));
    }
}

static int cb_out(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{

    u_int32_t id;
    struct packet_dhcp_desc dhcp_d;
    struct nfqnl_msg_packet_hdr *ph;
    memset(&dhcp_d,0,sizeof(dhcp_d));
    
    if ((ph = nfq_get_msg_packet_hdr(nfa)))
    {
        id = ntohl(ph->packet_id);
    }

    if ((exchange_packet_for_client(nfa, data, &dhcp_d))<0) {
        syslog(LOG_ERR,"Wrong packet or configuration!");
        return (nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL ));
    }
    else
    {
    return (nfq_set_verdict(qh, id, NF_ACCEPT, dhcp_d.len,dhcp_d.packet ));
    }
}

int main(int argc, char **argv)
{

    int pid;
    struct namelist * data_ipv4 = NULL, * data_ipv6 = NULL;
    char *path=DEFAULT_PATH;
    pthread_t thread_v4,thread_v6;
    int opt;

    while ((opt = getopt(argc, argv, "d:")) != -1)
    {
        switch (opt)
        {
        case 'd':
            path = optarg;
            break;
        default: /* '?' */
            printf("Usage: %s [-d ] /path/to/file\n",
                   argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (optind>argc)
    {
        printf("Expected argument after options\n");
        exit(-1);
    }

    if ((pid = fork()) != 0)
    {
        exit(-1);
    }
    else if (-1 == pid)
    {
        syslog(LOG_ERR,"Fork failed!");
        exit(-1);
    }
    else
    {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
    }

    if (parse_config(path, &data_ipv4, &data_ipv6)<0)
    {
        syslog(LOG_ERR, "Can't create config!!!");
        exit(-1);
    }

    if ((pthread_create(&(thread_v4), NULL, thread_dhcp_proxy, data_ipv4)) != 0 )
        syslog(LOG_ERR, "Can't create thread for ipv4!!!");

    if ((pthread_create(&(thread_v6), NULL, thread_dhcp_proxy6, data_ipv6)) != 0 )
        syslog(LOG_ERR, "Can't create thread for ipv6!!!");

    pthread_join(thread_v4, NULL);
    pthread_join(thread_v6, NULL);
    return(0);
}

void * thread_dhcp_proxy(void* thread_data)
{

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfq_handle *h_out;
    struct nfq_q_handle *qh_out;
    struct namelist_analisys data;
    char buf[PACK_LEN];
    fd_set rfds;
    int retval, fd_max, fd_out, fd, rv, interface=4;

    syslog(LOG_DEBUG, "opening library handle\n");
    h = nfq_open();
    if (!h)
    {
        syslog(LOG_ERR, "error during nfq_open()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0)
    {
        syslog(LOG_ERR, "error during nfq_unbind_pf()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0)
    {
        syslog(LOG_ERR, "error during nfq_bind_pf()\n");
        exit(-1);
    }

    data.ip_ver=4;
    data.interf_list = thread_data;

    syslog(LOG_DEBUG, "binding this socket to queue '4'\n");
    qh = nfq_create_queue(h,  4, &cb, &data);
    if (!qh)
    {
        syslog(LOG_ERR, "error during nfq_create_queue()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        syslog(LOG_ERR, "can't set packet_copy mode\n");
        exit(-1);
    }

    fd = nfq_fd(h);
//________________________________________________________________

    syslog(LOG_DEBUG, "opening library handle\n");
    h_out = nfq_open();
    if (!h_out)
    {
        syslog(LOG_ERR, "error during nfq_open()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h_out, AF_INET) < 0)
    {
        syslog(LOG_ERR, "error during nfq_unbind_pf()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h_out, AF_INET) < 0)
    {
        syslog(LOG_ERR, "error during nfq_bind_pf()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "binding this socket to queue '5'\n");
    qh_out = nfq_create_queue(h_out,  5, &cb_out, &interface);
    if (!qh_out)
    {
        syslog(LOG_ERR, "error during nfq_create_queue()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "setting copy_packet mode\n");
    if (nfq_set_mode(qh_out, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        syslog(LOG_ERR, "can't set packet_copy mode\n");
        exit(-1);
    }

    fd_out = nfq_fd(h_out);

//________________________________________________________________

    if (fd_out>fd) 
        fd_max = fd_out;
    else fd_max = fd;
    

    while(1) {
        FD_ZERO(&rfds);
        FD_SET(fd_out, &rfds);
        FD_SET(fd, &rfds);
    
        retval = select(fd_max+1, &rfds, NULL, NULL, NULL);
        if (retval < 0)  {
            syslog(LOG_ERR, "selects mastake is occured\n");
            break;
        }

        if (FD_ISSET( fd, &rfds)){
            rv = recv(fd, buf, sizeof(buf), 0);
            nfq_handle_packet(h, buf, rv);
            memset(buf,0,PACK_LEN);
        }
        else if (FD_ISSET(fd_out, &rfds)){
            rv = recv(fd_out, buf, sizeof(buf), 0);
            nfq_handle_packet(h_out, buf, rv);
            memset(buf,0,PACK_LEN);
        }
        else {
           syslog(LOG_DEBUG, "Wrong settings!\n");
           break; 
        }
    }
    
    nfq_destroy_queue(qh);
    syslog(LOG_DEBUG, "unbinding from queue 4\n");
    nfq_destroy_queue(qh_out);
    syslog(LOG_DEBUG, "unbinding from queue 5\n");
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */

    nfq_unbind_pf(h, AF_INET);
    nfq_unbind_pf(h_out, AF_INET);
    syslog(LOG_DEBUG, "unbinding from AF_INET\n");
    nfq_close(h);
    nfq_close(h_out);
    syslog(LOG_DEBUG,"closing library handle");
    syslog(LOG_DEBUG, "closing library handle\n");
    remove_namelist(data.interf_list);
    exit (0);
}

void * thread_dhcp_proxy6(void* thread_data)
{
    
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfq_handle *h_out;
    struct nfq_q_handle *qh_out;
    struct namelist_analisys data;
    char buf[PACK_LEN];
    fd_set rfds;
    int retval, fd_max, fd_out, fd, rv, interface=6;

    syslog(LOG_ERR,"opening library handle");
    h = nfq_open();
    if (!h)
    {
        syslog(LOG_ERR, "error during nfq_open()");
        exit (-1);
    }

    syslog(LOG_DEBUG,"unbinding existing nf_queue handler for AF_INET6 (if any)");
    if (nfq_unbind_pf(h, AF_INET6) < 0)
    {
        syslog(LOG_ERR, "error during nfq_unbind_pf()\n");
        exit (-1);
    }

    syslog(LOG_DEBUG,"binding nfnetlink_queue as nf_queue handler for AF_INET6");
    if (nfq_bind_pf(h, AF_INET6) < 0)
    {
        syslog(LOG_ERR, "error during nfq_bind_pf()\n");
        exit (-1);
    }

    data.ip_ver=6;
    data.interf_list = thread_data;

    syslog(LOG_DEBUG,"binding this socket to queue '1'");

    qh = nfq_create_queue(h,  1, &cb,  &data);
    if (!qh)
    {
        syslog(LOG_ERR, "error during nfq_create_queue()");
        exit (-1);
    }

    syslog(LOG_DEBUG,"setting copy_packet mode");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        syslog(LOG_ERR, "can't set packet_copy mode");
        exit (-1);
    }

    fd = nfq_fd(h);

    //________________________________________________________________

    syslog(LOG_DEBUG, "opening library handle\n");
    h_out = nfq_open();
    if (!h_out)
    {
        syslog(LOG_ERR, "error during nfq_open()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h_out, AF_INET6) < 0)
    {
        syslog(LOG_ERR, "error during nfq_unbind_pf()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h_out, AF_INET6) < 0)
    {
        syslog(LOG_ERR, "error during nfq_bind_pf()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "binding this socket to queue '2'\n");
    qh_out = nfq_create_queue(h_out,  2, &cb_out, &interface);
    if (!qh_out)
    {
        syslog(LOG_ERR, "error during nfq_create_queue()\n");
        exit(-1);
    }

    syslog(LOG_DEBUG, "setting copy_packet mode\n");
    if (nfq_set_mode(qh_out, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        syslog(LOG_ERR, "can't set packet_copy mode\n");
        exit(-1);
    }

    fd_out = nfq_fd(h_out);


    //________________________________________________________________
   
    if (fd_out>fd) 
        fd_max = fd_out;
    else fd_max = fd;

    
    while(1) {
        FD_ZERO(&rfds);
        FD_SET(fd_out, &rfds);
        FD_SET(fd, &rfds);
    
        retval = select(fd_max+1, &rfds, NULL, NULL, NULL);
        if (retval < 0)  {
            syslog(LOG_ERR, "selects mastake is occured\n");
            break;
        }

        if (FD_ISSET( fd, &rfds)){
            rv = recv(fd, buf, sizeof(buf), 0);
            nfq_handle_packet(h, buf, rv);
            memset(buf,0,PACK_LEN);
        }
        else if (FD_ISSET(fd_out, &rfds)){
            rv = recv(fd_out, buf, sizeof(buf), 0);
            if ((nfq_handle_packet(h_out, buf, rv))!=0) break ;            
            memset(buf,0,PACK_LEN);
        }
       else {
           syslog(LOG_DEBUG, "Wrong settings!\n");
           break; 
        }
    }
    
    nfq_destroy_queue(qh);
    syslog(LOG_DEBUG,"unbinding from queue 1");
    nfq_destroy_queue(qh_out);
    syslog(LOG_DEBUG,"unbinding from queue 2");

    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    
    nfq_unbind_pf(h, AF_INET6);
    nfq_unbind_pf(h_out, AF_INET6);
    syslog(LOG_DEBUG,"unbinding from AF_INET6");
    nfq_close(h);
    nfq_close(h_out);
    syslog(LOG_DEBUG,"closing library handle");
    remove_namelist(data.interf_list);
    exit(0);
    
}

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

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
    ptr += sizeof (iphdr.ip6_src.s6_addr);
    chksumlen += sizeof (iphdr.ip6_src.s6_addr);

    // Copy destination IP address into buf (128 bits)
    memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
    ptr += sizeof (iphdr.ip6_dst.s6_addr);
    chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

    // Copy UDP length into buf (32 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy zero field to buf (24 bits)
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 3;

    // Copy next header field to buf (8 bits)
    memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
    ptr += sizeof (iphdr.ip6_nxt);
    chksumlen += sizeof (iphdr.ip6_nxt);

    // Copy UDP source port to buf (16 bits)
    memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
    ptr += sizeof (udphdr.source);
    chksumlen += sizeof (udphdr.source);

    // Copy UDP destination port to buf (16 bits)
    memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
    ptr += sizeof (udphdr.dest);
    chksumlen += sizeof (udphdr.dest);

    // Copy UDP length again to buf (16 bits)
    memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
    ptr += sizeof (udphdr.len);
    chksumlen += sizeof (udphdr.len);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++)
    {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }
    return (checksum ((uint16_t *) buf, chksumlen));
}

int remove_namelist(struct namelist * root)
{
    struct namelist *ptr=NULL;
    while (root!=NULL)
    {
        ptr=root->next;
        free(root);
        root=ptr;
    }
    return (1);
}

