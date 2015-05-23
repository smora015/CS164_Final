#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>  // Used for handling SIGINT (ctrl+c)
#include <pthread.h> // pthread functions & data for parallelism

int sockfd;            // Socket file descriptor
int newsockfd;         // New socket file descriptor



void handle_signal( int signal )
{
  // Find out which signal we're handling
  switch (signal) {
  case SIGHUP:
    break;
  case SIGUSR1:
    break;
  case SIGINT:
    printf("Caught SIGINT, exiting now\n");
    close(sockfd);
    close(newsockfd);
    exit(0);
  default:
    fprintf(stderr, "Caught wrong signal: %d\n", signal);
    return;
  }
}

// Specifies error messages and ends program
void error(const char *msg)
{
  perror(msg);
  exit(1);
}

int main(int argc, char *argv[])
{
  // Signal handler 
  struct sigaction sa;
  sa.sa_handler = &handle_signal;

  // Set up variables for sockets
  int portno = 7158;     // Port #

  socklen_t clilen;      // Length of cli_addr struct
  char buffer[256];      // Buffer to hold messages

  struct sockaddr_in serv_addr, cli_addr; // Holds address of servers and clients
  int n;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);  // Create a new TCP socket
  if (sockfd < 0) 
    error("ERROR opening socket");

  bzero((char *) &serv_addr, sizeof(serv_addr)); // Clear struct
  serv_addr.sin_family = AF_INET;                // TCP
  serv_addr.sin_addr.s_addr = INADDR_ANY;        // Specify any available interface
  serv_addr.sin_port = htons(portno);            // Port #

  if (bind(sockfd, (struct sockaddr *) &serv_addr, // Bind the socket
	   sizeof(serv_addr)) < 0) 
    error("ERROR on binding");

  listen(sockfd,5);                             // Start listening for clients (max 5)
  clilen = sizeof(cli_addr);

  pid_t pid = 0;
  for(;;)
  {
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    // Fork a new process whenever a new client connects
    if ((pid = fork()) == -1)
    {
      close(newsockfd);
      continue;
    }
    else if(pid > 0) // Parent/Server process
    {

      close(newsockfd);
      continue;
    }
    else if(pid == 0) // Child/Client process
    {
      // Socket failed to accept to client
      if (newsockfd < 0) 
	error("ERROR on accept");

      for( ;; )
      {
	// Read from client
	bzero(buffer,256);
	
	n = read(newsockfd,buffer,255);
	if (n < 0) 
	  error("ERROR reading from socket");

	int ret = strncmp(buffer,"quit",4);
	printf("ret for %s is: %i\n", buffer, ret);
	 
	if( ret == 0 )
	{
	  printf("Client logged out...");

	  // Write to client
	  n = write(newsockfd,"Logged out successfully.",24);
	  if (n < 0)
	    error("ERROR writing to socket");
	  
	  close(newsockfd);
	  break;
	}
	else
	  printf("Here is the message: %s",buffer);

	// Write to client
	n = write(newsockfd,"I got your message",18);
	if (n < 0) error("ERROR writing to socket");

      }
    }
  }

  close(newsockfd);
  close(sockfd);
  return 0; 
}
