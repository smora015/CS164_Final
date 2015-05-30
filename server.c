#include <stdio.h> 
#include <stdlib.h> // Memory allocation, free, etc
#include <string.h>
#include <unistd.h>

#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>  // Used for handling SIGINT (ctrl+c)
#include <pthread.h> // pthread functions & data for parallelism

#include "server.h"


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

  // Bind the socket
  if (bind(sockfd, (struct sockaddr *) &serv_addr, // Bind the socket
	   sizeof(serv_addr)) < 0) 
    error("ERROR on binding");

  // Set up server to listen (up to 5 clients)
  listen(sockfd,5);                           
  clilen = sizeof(cli_addr);

  // Set up hard coded users
  init_users();

  // Start receiving messages
  printf("Successfully binded to hostname/port!\n" );
  pid_t pid = 0;
  for(;;)
  {
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    printf("Accepted port!\n");
    // Fork a new process whenever a new client connects
    if ((pid = fork()) == -1)
    {
      //don't go here!
      continue;
    }
    else if(pid > 0) // Parent/Server process
    {
      //printf("Parent PID.\n");
      continue;
    }
    else if(pid == 0) // Child/Client process
    {
      // Socket failed to accept to client
      if (newsockfd < 0) 
	error("ERROR on accept");

      printf("authenticating user...\n");
      // Authenticate the user
      if( is_authenticated( &newsockfd ) == 0 )
	authenticate_user( &newsockfd );

      printf("done authenticating user...\n");
      for( ;; ) {

      // Display menu
      int current_menu = 0; // 0 = main menu, etc
      display_menu( &newsockfd, &current_menu );
	
      // Get reply from client
      bzero(buffer,256);
      n = read(newsockfd,buffer,255);
      if (n < 0) 
	error("ERROR reading from socket");

      if( strncmp(buffer,"quit",4) == 0 )
      {
	printf("Status: [Client %i] - Logged out...\n", newsockfd);

	// Write to client
	n = write(newsockfd,"Logged out successfully.",24);
	if (n < 0)
	  error("ERROR writing to socket");
	  
	close(newsockfd);
	break;
      }
      else
	printf("From [Client %i] - %s\n", newsockfd, buffer);

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

// Specifies error messages and ends program
void error(const char *msg)
{
  perror(msg);
  exit(1);
}

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


user create_user( char* username, char* password, int sockfd, message* messages)
{
  user new_user;
  new_user.username = username;
  new_user.password = password;
  new_user.sockfd = sockfd;
  new_user.messages = messages;

  return new_user;
}

void init_users()
{
  // Allocate enough space in users list for 5 clients
  users = (user*) malloc( sizeof(user)*MAX_USERS );
  users_online = (user*) malloc( sizeof(user)*MAX_USERS );
  
  // Hard code 3 users
  user tom = create_user( "tom", "tom_password", -1, NULL);
  user chris = create_user( "chris", "chris_password", -1, NULL);
  user sara  = create_user( "sara", "sara_password", -1, NULL);

  users[0] = tom;
  users[1] = chris;
  users[2] = sara;

  // Initialize any counters or flags
  messagecount = 0;
  
}

int is_authenticated( int* sockfd )
{
  // Traverse through list of users to see if socket matches any users
  user* usr = users;
  while( usr->username != NULL )
  {
    if( usr->sockfd == *sockfd )
      return 1; // User was found, return 1

    ++usr; // Iterate to next user
  }

  printf("Ending is_authenticated...\n");
  // Else, user was not found, return 0
  return 0;
}

// Logs in the user to post tweets
int authenticate_user( int* sockfd )
{
  // Message prompts
  char* un = "Username: ";
  char* ps = "Password: ";
  char* iv = "Invalid username or password!";
  char ss[180];
  char* ss1 = "\nSuccessfully logged in! Welcome, ";
  user* usr; // Used to traverse list of users
  int found = 0;
  int n = 0;

  char username[255];
  char password[255];
  while( found == 0)
  {    
    usr = users; // Used to traverse list of users
    found = 0;

    printf("inside authenticate_user...\n");
    // Prompt for username
    n = write(*sockfd, un, strlen(un));

    // Get username
    bzero(username,256);
    n = read(*sockfd,username,255);
  
    // Prompt for password
    n = write(*sockfd, ps, strlen(ps));

    // Get password
    bzero(password, 256);
    n = read(*sockfd,password,255);

    // Traverse for user in list
    usr = users;
    while( usr->username != NULL )
    {
      // Compare username entered with username in list, providing the lenght of the username in the list.
      if( (strncmp(username,usr->username, strlen(usr->username) ) == 0) &&
	  (strncmp(password,usr->password, strlen(usr->password) ) == 0) ) 
      {
	found = 1; // Set found flag to true
	usr->sockfd = *sockfd; // Add current socket associated to user
	strcat( strcat( strcat(ss, ss1), usr->username ), "\n");
      }
      ++usr; // Iterate to next user
    }
    
    // If user could not be validated, display invalid message and loop back
    if( found == 0 )
      n = write(*sockfd, iv, strlen(iv));
  }

  // Display successful login message
  n = write(*sockfd, ss, strlen(ss));
}

void display_menu( int* sockfd, int* menu )
{
  char* main_msg = "============================\n Welcome to the CS164 Twitter Clone! \n============================\n";
  // Write to client
  int n = write(*sockfd,main_msg,strlen(main_msg));
  if (n < 0) error("ERROR writing to socket");
  

  return;
}
