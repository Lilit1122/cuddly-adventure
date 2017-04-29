//gcc parser.c -o -rpath -lcjson -lm -I=/usr/local/include -o parser
//export LD_LIBRARY_PATH
//gcc -c  parser1.c -lcjson -lm
// -I=/usr/local/include 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>


#define FULL_IFACE_NAME_SIZE 50
#define LINUX_NAME_LEN 16

struct namelist {
    int port;
    char name[FULL_IFACE_NAME_SIZE];
    int if_index;
    struct namelist * next;
};

int parse_config(char * , struct namelist **, int );
static int fill_struct(cJSON * , struct namelist ** , int );
