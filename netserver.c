#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h> 
#include <pthread.h>

#define BUF_SIZE 256
#define  MD5_DIGEST_LEN 16
void *ThreadMain(void *arg );  // Main program of a thread

// Structure of arguments to pass to client thread
struct ThreadArgs {
  int clntSock; // Socket descriptor for client
  char * filename;
  int filename_len;
};

int main(int argc, char ** argv)
{
     int sock, newsock, port, clen;
     struct sockaddr_in serv_addr, cli_addr;   
     struct ThreadArgs *threadArgs;
 

     if (argc < 3) 
     {
         fprintf(stderr,"usage: %s <port_number> <send_file_name>\n", argv[0]);
         return EXIT_FAILURE;
     }
     sock = socket(AF_INET, SOCK_STREAM, 0);   //Server sovket here!!!
     if (socket < 0)
     {
       printf("socket() failed: %d\n", errno);
       return EXIT_FAILURE;
     }


    
     memset((char *) &serv_addr, 0, sizeof(serv_addr));
     port = atoi(argv[1]);
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(port);
     if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
     {
       printf("bind() failed: %d\n", errno);
       return EXIT_FAILURE;
     }

  

      for (;;) {

     listen(sock, 3);    //The  main part
     clen = sizeof(cli_addr);
     newsock = accept(sock, (struct sockaddr *) &cli_addr, &clen);
     if (newsock < 0) 
     {
       printf("accept() failed: %d\n", errno);
       return EXIT_FAILURE;
     }

     threadArgs = (struct ThreadArgs *) malloc(sizeof(struct ThreadArgs));
     if (threadArgs == NULL)
      printf("malloc() failed");
    
     threadArgs->clntSock =  newsock;
     threadArgs->filename = argv[2];
     threadArgs->filename_len = sizeof(argv[2]);

     // Create client thread
     pthread_t threadID;
     int returnValue = pthread_create(&threadID, NULL, ThreadMain, threadArgs);
     if (returnValue != 0) printf("pthread_create() failed");
     printf("Client address: %s\n",inet_ntoa(cli_addr.sin_addr));
     printf("with thread %ld\n", (long int) threadID);
     }
     //close(sock);

}


void *ThreadMain(void *threadArgs) {
  // Guarantees that thread resources are deallocated upon return
  char buf[BUF_SIZE];
  unsigned char result[MD5_DIGEST_LEN];

  pthread_detach(pthread_self());
  int newsock = ((struct ThreadArgs *) threadArgs)->clntSock;
 // printf("newsock id: %d",newsock);
  memset(buf, 0, BUF_SIZE);

  write(newsock, ((struct ThreadArgs *) threadArgs)->filename, ((struct ThreadArgs *) threadArgs)->filename_len);   

  recv(newsock, result, sizeof(result), 0);
  printf("%s MD5 Checksumm: ", ((struct ThreadArgs *) threadArgs)->filename );
  for(int i=0; i <MD5_DIGEST_LEN; i++) { //?
            printf("%02x",result[i]);
    }
  printf("\n"); 
  close(newsock);
  
  return (NULL);
}

void DieWithError(char *errorMessage)
{
    perror(errorMessage);
    exit(1);
}



