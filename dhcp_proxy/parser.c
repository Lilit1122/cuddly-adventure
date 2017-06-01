#include "parser.h"

static int fill_struct(cJSON * root_json, struct namelist ** dhcpv6, struct namelist ** dhcpv4)
{
    if (root_json == NULL) return -1;
    //if (root == NULL)      return -1;
    cJSON * ip_interface  = NULL;
    cJSON * ip_interfaces = NULL;
    cJSON * server_port_dhcp_6  = NULL;
    cJSON * relay_port_dhcp_6 = NULL;
    cJSON * dhcp_relay_6 = NULL;
    cJSON * dhcp_server_6 =NULL;
    cJSON * dhcp_proxy = NULL;
    cJSON * dhcp_proxy_enable = NULL;
    cJSON * dhcp_mode_6 = NULL;
    cJSON * relay_addrs = NULL;
    struct namelist *new_interface_6 = NULL;

    //if (root == NULL)      return -1;
    cJSON * interface  = NULL;
    cJSON * interfaces = NULL;
    cJSON * server_port_dhcp  = NULL;
    cJSON * relay_port_dhcp = NULL;
    cJSON * dhcp_relay = NULL;
    cJSON * dhcp_server =NULL;
    cJSON * dhcp_mode = NULL;
    cJSON * helper_addrs = NULL;
    struct namelist *new_interface = NULL;

    dhcp_proxy = cJSON_GetObjectItem(root_json, "dhcp-proxy");
    if (dhcp_proxy == NULL)
    {
        syslog(LOG_ERR, "No have 'dhcp-proxy'");
        return 0;
    }

    dhcp_proxy_enable = cJSON_GetObjectItem(dhcp_proxy, "enable");
    if (dhcp_proxy_enable == NULL)
    {
        syslog(LOG_ERR, "Wrong json file. No have 'dhcp-proxy-enable'");
        return -1;
    }

    if (dhcp_proxy_enable->type != cJSON_True)
    {
        syslog(LOG_ERR,"dhcp-proxy disable");
        return 0;
    }

// Fill in dhcp_server_port_6, relay_port_dhcp
    dhcp_server_6 = cJSON_GetObjectItem(dhcp_proxy, "dhcp6-server");
    if ( dhcp_server_6 == NULL)
    {
        syslog(LOG_ERR, "Wrong json file. No have 'dhcp_server_6'");
        return -1;
    }

    server_port_dhcp_6 = cJSON_GetObjectItem(dhcp_server_6, "port");
    if (server_port_dhcp_6 == NULL)
    {
        syslog(LOG_ERR, "Wrong json file. No have 'interfaces'");
        return -1;
    }
    int dhcp_server_port_6 = server_port_dhcp_6 -> valueint;

    dhcp_relay_6 = cJSON_GetObjectItem(dhcp_proxy, "dhcp6-relay");
    if (dhcp_relay_6 == NULL)
    {
        syslog(LOG_ERR, "'Dhcp6_relay' is disable");
        return -1;
    }

    relay_port_dhcp_6 = cJSON_GetObjectItem(dhcp_relay_6, "port");
    if (relay_port_dhcp_6 == NULL)
    {
        syslog(LOG_ERR, "Wrong json file. No have 'relay_port_dhcp'");
        return -1;
    }
    int relay_port_6 = relay_port_dhcp_6->valueint;

    dhcp_server = cJSON_GetObjectItem(dhcp_proxy, "dhcp-server");
    if ( dhcp_server == NULL)
    {
        syslog(LOG_ERR,  "Wrong json file. No have 'dhcp_server'");
        return (-1);
    }

    server_port_dhcp = cJSON_GetObjectItem(dhcp_server, "port");
    if (server_port_dhcp == NULL)
    {
        syslog(LOG_ERR,  "Wrong json file. No have 'interfaces'");
        return (-1);
    }
    int dhcp_server_port = server_port_dhcp -> valueint;

    dhcp_relay = cJSON_GetObjectItem(dhcp_proxy, "dhcp-relay");
    if (dhcp_relay == NULL)
    {
        syslog(LOG_ERR,  "'Dhcp_relay' is disable");
        return (-1);
    }

    relay_port_dhcp = cJSON_GetObjectItem(dhcp_relay, "port");
    if (relay_port_dhcp == NULL)
    {
        syslog(LOG_ERR,  "Wrong json file. No have 'relay_port_dhcp'");
        return (-1);
    }
    int relay_port = relay_port_dhcp->valueint;

    ip_interfaces = cJSON_GetObjectItem(root_json, "ip-interfaces");
    if (ip_interfaces == NULL)
    {
        syslog(LOG_ERR, "Wrong json file. No have 'ip-interfaces'");
        return -1;
    }

    int interface_idx = 0;
    struct namelist * ptr;
    while (NULL != (ip_interface = cJSON_GetArrayItem(ip_interfaces, interface_idx++)))
    {
        if (ip_interface->type != cJSON_Object)
        {
            syslog(LOG_ERR,"unknown subelement type in 'ip-interfaces' object(%d)", ip_interface->type);
            return -1;
        }
        dhcp_mode_6 = cJSON_GetObjectItem(ip_interface, "dhcp6-client");
        if (dhcp_mode_6  != NULL)
        {
            if ((strcmp(dhcp_mode_6->valuestring, "enable" ))!=0)
            {
                continue;
            }
        }

        int check = 0;
        ptr = *dhcpv6;
        while (ptr != NULL)
        {
            if  ((strcmp(ip_interface->string, ptr->name ))==0)
            {
                check = 1;
                break;
            }
            ptr = ptr->next;
        }

        if (check == 1) continue;

        new_interface_6 = namelist_creation(ip_interface->string);
        relay_addrs = cJSON_GetObjectItem(ip_interface, "dhcp6-relay");

        if (relay_addrs  != NULL)
        {
            new_interface_6->port = relay_port_6;
            new_interface_6->next = *dhcpv6;
            *dhcpv6 = new_interface_6;
            ptr = *dhcpv6;
            while (ptr != NULL)
            {
                if  ((strcmp(relay_addrs->valuestring, ptr->name ))==0)
                {
                    ptr->port = relay_port_6;
                    break;
                }
                if  (ptr->next == NULL)
                {

                    new_interface_6 = namelist_creation(relay_addrs->valuestring);
                    new_interface_6->port = relay_port_6;
                    new_interface_6->next = *dhcpv6;
                    *dhcpv6 = new_interface_6;

                }
                ptr = ptr->next;
            }
        }
        else
        {
            ptr = *dhcpv6;
            new_interface_6->port = dhcp_server_port_6;
            new_interface_6->next = *dhcpv6;
            *dhcpv6 = new_interface_6;
        }
    }
    print_namelist(*dhcpv6);

    interfaces = cJSON_GetObjectItem(root_json, "interfaces");
    if (interfaces == NULL)
    {
        syslog(LOG_ERR,  "Wrong json file. No have 'interfaces'");
        return (-1);
    }

    interface_idx = 0;
    ptr = NULL;
    while (NULL != (interface = cJSON_GetArrayItem(interfaces, interface_idx++)))
    {
        if (interface->type != cJSON_Object)
        {
            syslog(LOG_ERR, "unknown subelement type in 'interfaces' object(%d)", interface->type);
            return (-1);
        }
        dhcp_mode = cJSON_GetObjectItem(interface, "dhcp_mode");
        if (dhcp_mode  != NULL)
        {
            if ((strcmp(dhcp_mode->valuestring, "enable" ))!=0)
            {
                continue;
            }
        }

        int check = 0;
        ptr = *dhcpv4;
        while (ptr != NULL)
        {
            if  ((strcmp(interface->string, ptr->name ))==0)
            {
                check = 1;
                break;
            }
            ptr = ptr->next;
        }

        if (check == 1) continue;

        new_interface = namelist_creation(interface->string);
        helper_addrs = cJSON_GetObjectItem(interface, "dhcp-relay");

        if (helper_addrs  != NULL)
        {
            new_interface->port = relay_port;

            new_interface->next = *dhcpv4;
            *dhcpv4 = new_interface;
            ptr = *dhcpv4;
            while (ptr != NULL)
            {
                if  ((strcmp(helper_addrs->valuestring, ptr->name ))==0)
                {
                    ptr->port = relay_port;
                    break;
                }
                if  (ptr->next == NULL)
                {

                    new_interface = namelist_creation(helper_addrs->valuestring);
                    new_interface->port = relay_port;
                    new_interface->next = *dhcpv4;
                    *dhcpv4 = new_interface;
                }
                ptr = ptr->next;
            }
        }
        else
        {
            ptr = *dhcpv4;

            new_interface->port = dhcp_server_port;
            new_interface->next = *dhcpv4;
            *dhcpv4 = new_interface;
        }
    }
    print_namelist(*dhcpv4);

    return 0;
}


int parse_config(char * filename, struct namelist ** dhcpv4, struct namelist ** dhcpv6)
{

    char * text = NULL;
    FILE * f = NULL;
    cJSON * root_json = NULL;

    int free_and_exit(int rc)
    {
        if (text) free(text);
        if (f) fclose(f);
        if (root_json) cJSON_Delete(root_json);

        return rc;
    }

    f = fopen(filename, "r");
    if (f == NULL)
    {
        if (errno == ENOENT)
        {
            syslog(LOG_ERR, "<%s> file '%s' not exist", __FUNCTION__, filename);
            return free_and_exit(-1);
        }
        else
        {
            syslog(LOG_ERR, "<%s> can't open '%s' (%s)", __FUNCTION__, filename, strerror(errno));
            return free_and_exit(-1);
        }
    }
    if (f == NULL)
    {
        if (errno == ENOENT)
        {
            syslog(LOG_ERR, "<%s> file '%s' not exist", __FUNCTION__, filename);
            return free_and_exit(-1);
        }
        else
        {
            syslog(LOG_ERR, "<%s> can't open '%s' (%s)", __FUNCTION__, filename, strerror(errno));
            return free_and_exit(-1);
        }
    }

    if (0 != fseek(f, 0, SEEK_END))
    {
        syslog(LOG_ERR, "<%s> fseek failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }
    long len = ftell(f);
    if (-1 == len)
    {
        syslog(LOG_ERR, "<%s> ftell failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }
    if (0 != fseek(f, 0, SEEK_SET))
    {
        syslog(LOG_ERR,"<%s> fseek failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }

    text = (char *)malloc(len + 1);
    if (text == NULL)
    {
        syslog(LOG_ERR, "<%s> No free space!", __FUNCTION__);
        return free_and_exit(-1);
    }

    long read = fread(text, 1, len, f);

    if (ferror(f))
    {
        syslog(LOG_ERR,"<%s> fread failed %ld != %ld (%s)", __FUNCTION__, read, len, strerror(errno));
        return free_and_exit(-1);
    }

    if (read != len)
    {
        syslog(LOG_ERR,"<%s> fread failed %ld != %ld (%s)", __FUNCTION__, read, len, strerror(errno));
        return free_and_exit(-1);
    }
    text[len] = '\0';

    root_json = cJSON_Parse(text);
    if (root_json == NULL)
    {
        syslog(LOG_ERR, "<%s> cJSON_Parse failed", __FUNCTION__);
        return free_and_exit(-1);
    }

    if (0 != fill_struct(root_json, dhcpv6, dhcpv4))
    {
        syslog(LOG_ERR, "<%s> fill_struct failed", __FUNCTION__);
        return free_and_exit(-1);
    }

    fclose(f);

    return (0);
}

int print_namelist(struct namelist * root)
{
    struct namelist *ptr;
    ptr = root;
    while (ptr != NULL)
    {
        syslog(LOG_DEBUG,"Interface name %s\n", ptr->name);
        syslog(LOG_DEBUG,"if_index %d\n", ptr->if_index);
        syslog(LOG_DEBUG,"port %d\n",ptr->port);
        ptr=ptr->next;
    }
    return(1);
}

struct namelist * namelist_creation(char * interface_name)
{
    struct namelist * new_interface = NULL;
    new_interface =  malloc(sizeof(struct namelist));
    if (new_interface == NULL)
    {
        syslog(LOG_ERR,"<%s> No free space", __FUNCTION__);
        return NULL;
    }
    strncpy(new_interface->name, interface_name, LINUX_NAME_LEN);
    new_interface->if_index = if_nametoindex((const char *)new_interface->name);
    return new_interface;
}
