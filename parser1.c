#include "parser1.h"

static int fill_struct(cJSON * root_json, struct namelist ** root, int fd_for_if_index)
{
    if (root_json == NULL) return -1;
    //if (root == NULL)      return -1;

    cJSON * interface  = NULL;
    cJSON * interfaces = NULL;
    cJSON * server_port_dhcp  = NULL;
    cJSON * relay_port_dhcp = NULL;
    cJSON * dhcp_relay = NULL;
    cJSON * dhcp_server =NULL;
    cJSON * dhcp_proxy = NULL;
    cJSON * dhcp_proxy_enable = NULL;
    cJSON * dhcp_mode = NULL;
    cJSON * helper_addrs = NULL;
    struct ifreq ifr;
    struct namelist * new_interface = NULL;

    dhcp_proxy = cJSON_GetObjectItem(root_json, "dhcp-proxy");
    if (dhcp_proxy == NULL) {
        printf( "No have 'dhcp-proxy'");
        return 0;
    }

    dhcp_proxy_enable = cJSON_GetObjectItem(dhcp_proxy, "enable");
    if (dhcp_proxy_enable == NULL) {
        printf( "Wrong json file. No have 'dhcp-proxy-enable'");
        return -1;
    }

    if (dhcp_proxy_enable->type != cJSON_True) {
        printf("dhcp-proxy disable");
        return 0;
    }

// Fill in dhcp_server_port, relay_port_dhcp
    dhcp_server = cJSON_GetObjectItem(dhcp_proxy, "dhcp-server");
    if ( dhcp_server == NULL) {
        printf( "Wrong json file. No have 'dhcp_server'");
        return -1;
    }

    server_port_dhcp = cJSON_GetObjectItem(dhcp_server, "port");
    if (server_port_dhcp == NULL) {
        printf( "Wrong json file. No have 'interfaces'");
        return -1;
    }
    int dhcp_server_port = server_port_dhcp -> valueint;

    dhcp_relay = cJSON_GetObjectItem(dhcp_proxy, "dhcp-relay");
    if (dhcp_relay == NULL) {
        printf( "Wrong json file. No have 'dhcp_relay'");
        return -1;
    }

    relay_port_dhcp = cJSON_GetObjectItem(dhcp_relay, "port");
    if (relay_port_dhcp == NULL) {
        printf( "Wrong json file. No have 'relay_port_dhcp'");
        return -1;
    }
    int relay_port = relay_port_dhcp->valueint;

    interfaces = cJSON_GetObjectItem(root_json, "interfaces");
    if (interfaces == NULL) {
        printf( "Wrong json file. No have 'interfaces'");
        return -1;
    }

    int interface_idx = 0;

    while (NULL != (interface = cJSON_GetArrayItem(interfaces, interface_idx++))) {
        // printf("1");
        if (interface->type != cJSON_Object) {
            printf("unknown subelement type in 'interfaces' object(%d)", interface->type);
            return -1;
        }
        dhcp_mode = cJSON_GetObjectItem(interface, "dhcp_mode");
        if (dhcp_mode  != NULL) {
            if ((strcmp(dhcp_mode->string, "enable" ))!=0) {
                continue;
            }
        }

        new_interface =  malloc(sizeof(struct namelist));
        if (new_interface == NULL) {
            printf("<%s> No free space", __FUNCTION__);
            return -1;
        }

        memset(&ifr ,0, sizeof(struct ifreq) );
        memset(new_interface, 0, sizeof(struct namelist));
        strncpy(new_interface->name, interface->string, FULL_IFACE_NAME_SIZE);

        strncpy(ifr.ifr_name, interface->string, LINUX_NAME_LEN);

        helper_addrs = cJSON_GetObjectItem(interface, "helper-addrs");
        if (helper_addrs  != NULL) {
            new_interface->port = relay_port;
        }
        else new_interface->port = dhcp_server_port;

        printf("new_interface->name %s\n", new_interface->name );
        printf("ifr.ifr_name %s\n", ifr.ifr_name );

        ioctl(fd_for_if_index, SIOCGIFINDEX, &ifr) ;

        printf("ifr.ifr_ifindex %d\n",ifr.ifr_ifindex);

        new_interface->if_index = ifr.ifr_ifindex;

        new_interface->next = *root;
        *root = new_interface;

    }


    return 0;
}

int parse_config(char * filename, struct namelist ** root, int fd_for_if_index)
{
    char * text = NULL;
    FILE * f = NULL;
    cJSON * root_json = NULL;

    int free_and_exit(int rc) {
        if (text) free(text);
        if (f) fclose(f);
        if (root_json) cJSON_Delete(root_json);

        return rc;
    }

    f = fopen(filename, "r");
    if (f == NULL) {
        if (errno == ENOENT) {
            printf( "<%s> file '%s' not exist", __FUNCTION__, filename);
            return free_and_exit(-1);
        } else {
            printf( "<%s> can't open '%s' (%s)", __FUNCTION__, filename, strerror(errno));
            return free_and_exit(-1);
        }
    }

    if (0 != fseek(f, 0, SEEK_END)) {
        printf( "<%s> fseek failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }
    long len = ftell(f);
    if (-1 == len) {
        printf( "<%s> ftell failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }
    if (0 != fseek(f, 0, SEEK_SET)) {
        printf("<%s> fseek failed (%s)", __FUNCTION__, strerror(errno));
        return free_and_exit(-1);
    }

    text = (char *)malloc(len + 1);
    if (text == NULL) {
        printf( "<%s> No free space!", __FUNCTION__);
        return free_and_exit(-1);
    }

    long read = fread(text, 1, len, f);

    if (ferror(f)) {
        printf("<%s> fread failed %ld != %ld (%s)", __FUNCTION__, read, len, strerror(errno));
        return free_and_exit(-1);
    }

    if (read != len) {
        printf("<%s> fread failed %ld != %ld (%s)", __FUNCTION__, read, len, strerror(errno));
        return free_and_exit(-1);
    }
    text[len] = '\0';

    root_json = cJSON_Parse(text);
    if (root_json == NULL) {
        printf( "<%s> cJSON_Parse failed", __FUNCTION__);
        return free_and_exit(-1);
    }

    if (0 != fill_struct(root_json, root, fd_for_if_index)) {
        printf( "<%s> fill_struct failed", __FUNCTION__);
        return free_and_exit(-1);
    }

    return (0);
}
/*
int main()
{
    struct namelist * root = NULL, *r = NULL;
    printf("pum");

    parse_config("dhcp-proxy.conf",&root,);
    printf("pum2");
    r=root;
    while (root!=NULL) {
        printf("Inteface name %s\n", root->name );
        printf("Port %d\n", root->port);
        root = root->next;
    }
    r=root;
    while (r!=NULL) {
        struct namelist * m;
        m = r->next;
        free(r);
        r = m;
   }
   return 1;
}
*/
