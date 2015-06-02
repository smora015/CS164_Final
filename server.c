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
  int n = 0;             // Used to read/write from/to socket
      
  struct sockaddr_in serv_addr, cli_addr; // Holds address of servers and clients

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

  // Set up memory allocation, hard coded users, etc
  init_data();

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

      /*


	MUST IMPLEMENT SHARING GLOBAL MEMORY!!!!!! 
	http://stackoverflow.com/questions/13274786/how-to-share-memory-between-process-fork

      */

      // Socket failed to accept to client
      if (newsockfd < 0) 
	error("ERROR on accept");

      // Authenticate the user
      authenticate_user( &newsockfd );
      
      // Display main menu
      current_menu = 0; // 0 = main menu, etc
      handle_menu( &newsockfd, &current_menu ); 

      // Loop for handling replies and responses to/from client
      for( ;; ) 
      {	
	// Get command from client
	bzero(buffer,256);
	n = read( newsockfd, buffer, 255);
	if( n < 0) error("ERROR reading from socket");
	current_menu = atoi( (const char*) buffer ); 

	// Handle command
	if( current_menu != 5 )
	  handle_menu( &newsockfd, &current_menu );

	// Log out the user if they entered '5'
	else
	{
	  printf("[User %s] - Has logged off.\n", current_user->username);

	  // Write to client
	  int n = write( newsockfd,"Logged out successfully.",24);
	  if (n < 0)
	    error("ERROR writing to socket");

	  close(newsockfd);
	  break;
	}

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
  new_user.message_count = 0;

  return new_user;
}

user* get_current_user( int sockfd )
{
  user* usr = users;
  while( usr != NULL )
  {
    if( usr->sockfd == sockfd)
      return usr;

    ++usr; // Iterate to next user!
  }

  return NULL;
}
 
user* get_user( char* username )
{
  user* usr = users;
  while( usr != NULL )
  {
    if( strncmp( usr->username, username, strlen(username)) )
	return usr;

    ++usr; // Iterate to next user!
  }
  
  return NULL;
}

void init_data()
{
  // Allocate enough space in users list for 5 clients
  users = (user*) malloc( sizeof(user)*MAX_USERS );
  users_online = (user*) malloc( sizeof(user)*MAX_USERS );
  current_user = (user*) malloc( sizeof(*current_user) );


  // Hard code 3 users
  user tom = create_user( "tom", "tom_password", -1, NULL);
  user chris = create_user( "chris", "chris_password", -1, NULL);
  user sara  = create_user( "sara", "sara_password", -1, NULL);

  users[0] = tom;
  users[1] = chris;
  users[2] = sara;

  // Initialize any counters or flags
  messages_received = 0;
  
}

// Logs in the user to post tweets
int authenticate_user( int* sockfd )
{
  // Message prompts
  char* un = "Username: ";
  char* ps = "Password: ";
  char* iv = "Invalid username or password!\n";
  char ss[180];
  char* ss1 = "\nSuccessfully logged in! Welcome, ";
  char* ss2 = ".\nYou have ";
  char* ss3 = " messages.\n";
  user* usr; // Used to traverse list of users
  int found = 0;
  int n = 0;

  char username[255];
  char password[255];
  while( found == 0)
  {    
    usr = users; // Used to traverse list of users
    found = 0;

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

	strcat( strcat(ss, ss1), usr->username );        // Contantenate welcome message
	char mc[20];
	snprintf(mc, 20, "%d", usr->message_count);
	strcat( strcat( strcat( ss, ss2 ), mc ), ss3);

	current_user = (user*) malloc( sizeof(user) );   // Set current user
	current_user = get_current_user( *sockfd ); 
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

void handle_menu( int* sockfd, int* menu )
{
  int n;
  char buffer[255];

  // Get reply from client
  if( *menu == 0 ) // Main Menu
  {
    char* main_msg = "============================\n CS164 Twitter Clone - Main Menu \n============================\n\
1. Offline Messages\n2. Edit Subscriptions\n3. Post a message\n4. Hashtag search\n5. Logout (or 'quit'): ";

    // Display main message
    int n = write(*sockfd,main_msg,strlen(main_msg));
    if (n < 0) error("ERROR writing to socket");

  }  
  else if( *menu == 1 ) // See Offline Messages
  {
    char* main_msg = "============================\n CS164 Twitter Clone - Offline Messages \n============================\n0. Back";

    if( current_user->messages == NULL )
    {
      char * msg = "You have don't have any offline messages.\n";
      strcat( strcat( buffer, main_msg ), msg );

      n = write( *sockfd, buffer, strlen(buffer) );
      if( n < 0 ) error("ERROR writing to socket");
    }    
  }
  else if( *menu == 2 ) // Edit Subscriptions
  {
    
  }
  else if( *menu == 3 ) // Post a message
  {

  }
  else if( *menu == 4) // Hashtag search
  {

  }
  else
  {
    char* msg = "Invalid command. Re-enter: ";
    int n = write( *sockfd, msg, strlen(msg) );
    if( n < 0 ) error("ERROR writing socket!");

    n = read( *sockfd, buffer, 255 );
    if( n < 0 ) error("ERROR reading from socket!");
    *menu = atoi( (const char*) buffer );
  }
  return;
}

