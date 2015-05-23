#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include <netdb.h>

// Specifies error messages and ends program
void error(const char *msg)
{
  perror(msg);
  exit(1);
}

int main(int argc, char *argv[])
{
  // Set up variables for sockets
  int sockfd;            // Socket file descriptor
  int portno = 7158;     // Port #
  char buffer[256];      // Buffer to hold messages

  struct sockaddr_in serv_addr; // Holds address of server socket
  struct hostent *server = gethostbyname( "localhost" ); // Holds hostname of server
  int n;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);  // Create a new TCP socket
  if (sockfd < 0)
  {
    close(sockfd);
    error("ERROR opening socket");
  }

  bzero((char *) &serv_addr, sizeof(serv_addr)); // Clear struct
  serv_addr.sin_family = AF_INET;                // Specify internet domain
  bcopy((char *)server->h_addr,                  // Specify server hostname
	(char *)&serv_addr.sin_addr.s_addr,
	server->h_length);
  serv_addr.sin_port = htons(portno);            // Specify port #

  // Connect to server
  if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
  {
    close(sockfd);
    error("ERROR connecting");
  }

  for( ;; )
  {
    // Get message
    printf("Please enter the message: ");
    bzero(buffer,256);
    fgets(buffer,255,stdin);

    // Send to server
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) 
      {
	close(sockfd);
	error("ERROR writing to socket");
      }

    bzero(buffer,256);

    // Get response from server
    n = read(sockfd,buffer,255);
    if (n < 0) 
    {
      close(sockfd);
      error("ERROR reading from socket");
    }

    if( strncmp(buffer,"Logged out successfully.",24) == 0 )
    {
      printf( "%s\n", buffer );
      break;
    }
    else
      printf( "%s\n",buffer );

  }

  close(sockfd);
  return 0; 

}
