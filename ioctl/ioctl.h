typedef struct _RETURN_STRING {
   char buf[ 160 ];
} RETURN_STRING;

#define IOC_MAGIC    'h'
#define IOCTL_GET_STRING _IOR( IOC_MAGIC, 1, RETURN_STRING )
#define IOCTL_SET_STRING _IOW( IOC_MAGIC, 2, char * )

#define DEVPATH "/dev/ioctl"
