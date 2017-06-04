#ifndef PARSER_INCLUDE__
#define PARSER_INCLUDE__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "dhcp-proxy.h"

int parse_config(char * , struct namelist **, struct namelist ** );
int print_namelist(struct namelist * );
struct namelist * namelist_creation(char *);
#endif
