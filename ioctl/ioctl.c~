#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include "ioctl.h"

#define ERR(...) fprintf( stderr, "\7" __VA_ARGS__ ), exit( EXIT_FAILURE )

char user_str[160];
int main( int argc, char *argv[] ) {
   int dfd;                  // дескриптор устройства 
  
   RETURN_STRING buf;
   if( ( dfd = open( DEVPATH, O_RDWR ) ) < 0 ) ERR( "Open device error: %m\n" );
   if( ioctl( dfd, IOCTL_GET_STRING, &buf ) ) ERR( "IOCTL_SET_STRING error: %m\n" );
   fprintf( stdout, "%s\n", &buf );
   printf("Input your message:\n");
   scanf("%s", user_str);
   if( ioctl( dfd, IOCTL_SET_STRING, user_str ) ) ERR( "IOCTL_SET_STRING error: %m\n" );
   fprintf( stdout, "%s\n", user_str );
   close( dfd );

   return EXIT_SUCCESS;

};


