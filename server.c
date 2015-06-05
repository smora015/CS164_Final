#include <stdio.h> 
#include <stdlib.h> // Memory allocation, free, etc
#include <string.h>
#include <unistd.h>
#include <sys/wait.h> // Inter-process shared memory
#include <sys/mman.h>
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
    pid = fork();
    if ( pid < 0 )
    {
      error("fork()");
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
      authenticate_user();
 
      // Display main menu
      handle_menu(); 

     // Loop for handling replies and responses to/from client
      for( ;; ) 
      {	
	// Handle command
	if( current_menu != 5 )
	  handle_menu();

	// Log out the user if they entered '5'
	else
	{
	  printf("[User %s] - Has logged off.\n", current_user.username);

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


user create_user( char* username, char* password, int sockfd)
{
  user new_user;
  new_user.username = username;
  new_user.password = password;
  new_user.sockfd = sockfd;
  new_user.message_count = 0;

  return new_user;
}

user get_user( char* username )
{
  int i;
  char cmp[50];
  strcpy( cmp, username );

  for( i = 0; i < MAX_USERS; ++i )
  {
    if( strncmp( users[i].username, cmp, strlen(cmp)) == 0 )
      return users[i];
  }
  
  return create_user( NULL, NULL, -1);
}

void init_data()
{
  // Allocate enough space in users list for 5 clients
  //users = (user*) malloc( sizeof(user)*MAX_USERS );
  //users_online = (user*) malloc( sizeof(user)*MAX_USERS );

  // Allocate user lists and online user list as shared process memory
  users = mmap(NULL, sizeof * users * MAX_USERS, PROT_READ | PROT_WRITE, 
       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  users_online = mmap(NULL, sizeof * users_online * MAX_USERS, PROT_READ | PROT_WRITE, 
       MAP_SHARED | MAP_ANONYMOUS, -1, 0);


  // Hard code 3 users
  user tom = create_user( "tom", "tom_password", -1);
  user chris = create_user( "chris", "chris_password", -1);
  user sara  = create_user( "sara", "sara_password", -1);

  users[0] = tom;
  users[1] = chris;
  users[2] = sara;

  // Initialize any counters or flags
  messages_received = 0;
  current_menu = 0;
}

// Logs in the user to post tweets
void authenticate_user()
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
  int i = 0;

  char username[255];
  char password[255];
  while( found == 0)
  {    
    found = 0;

    // Prompt for username
    n = write(newsockfd, un, strlen(un));

    // Get username
    bzero(username,256);
    n = read(newsockfd,username,255);
  
    // Prompt for password
    n = write(newsockfd, ps, strlen(ps));

    // Get password
    bzero(password, 256);
    n = read(newsockfd,password,255);

    for( i = 0; i < 5; ++i )
    {
      if( users[i].username == NULL )
	break;

      // Compare username entered with username in list, providing the lenght of the username in the list.
      if( (strncmp(username, users[i].username, strlen(users[i].username) ) == 0) &&
	  (strncmp(password, users[i].password, strlen(users[i].password) ) == 0) ) 
      {
	found = 1; // Set found flag to true
	users[i].sockfd = newsockfd; // Add current socket associated to user

	strcat( strcat(ss, ss1), users[i].username );        // Contantenate welcome message
	char mc[20];
	snprintf(mc, 20, "%d", users[i].message_count);
	strcat( strcat( strcat( ss, ss2 ), mc ), ss3);

	current_user = get_user( users[i].username ); 
	printf("[User %s] - Is now online.\n", current_user.username);

	break;
      }

    }
    
    // If user could not be validated, display invalid message and loop back
    if( found == 0 )
      n = write(newsockfd, iv, strlen(iv));
  }

  // Display successful login message
  n = write(newsockfd, ss, strlen(ss));
}

void get_input()
{
  // Get command from client
  bzero(buffer,512);
  n = read( newsockfd, buffer, 512);
  if( n < 0) error("ERROR reading from socket");
}

void get_menu_input()
{
  // Get command from client
  bzero(buffer,512);
  n = read( newsockfd, buffer, 512);
  if( n < 0) error("ERROR reading from socket");

  if( strlen(buffer) == 0 )
    current_menu = 0;
  else
      current_menu = atoi( (const char*) buffer ); 
}

void handle_menu()
{
  int n;

  // Get reply from client
  if( current_menu == 0 ) // Main Menu
  {
    char* main_msg = "============================\n CS164 Twitter Clone - Main Menu \n============================\n\
1. Offline Messages\n2. Edit Subscriptions\n3. Post a message\n4. Hashtag search\n5. Logout (or 'quit')\n> ";

    // Display main message
    n = write( newsockfd,main_msg,strlen(main_msg));
    if (n < 0) error("ERROR writing to socket");

    // Read input from socket
    get_menu_input();

  }  
  else if( current_menu == 1 ) // See Offline Messages
  {
    handle_offline_messages();
  }
  else if( current_menu == 2 ) // Edit Subscriptions
  {
    handle_subscriptions();
  }
  else if( current_menu == 3 ) // Post a message
  {
    handle_post_message();
  }
  else if( current_menu == 4) // Hashtag search
  {
    handle_hashtags();
  }
  else // Invalid input
  {
    char* msg = "\n>";
    n = write( newsockfd, msg, strlen(msg) );
    if( n < 0 ) error("ERROR writing socket!");

    // Read input from socket
    get_menu_input();

  }
  return;
}


void handle_offline_messages()
{
  char* main_msg = "============================\n CS164 Twitter Clone - Offline Messages \n============================\n0. Back\n";
  while( current_menu != 0 )
  {
    if( current_user.messages[0].message == NULL )
    {
      char * msg = "You have don't have any offline messages.\n> ";
      bzero(buffer,512);
      strcat( strcat( buffer, main_msg ), msg );
      
      n = write( newsockfd, buffer, strlen(buffer) );
      if( n < 0 ) error("ERROR writing to socket");
    }
    else
    {
      char * msg = "You HAVE offline messages. Displaying...\n> ";
      bzero(buffer,512);
      strcat( strcat( buffer, main_msg ), msg );
      
      n = write( newsockfd, buffer, strlen(buffer) );
      if( n < 0 ) error("ERROR writing to socket");
    }
    
    // Read input from socket
    get_menu_input();
    
  }
  
}

char* get_current_subscriptions()
{
  bzero(buffer, 512); // Store all available subs in buffer
  char** sub;         // Pointer to subscriptions

  sub = current_user.subs;
  int i;
  for( i = 0; i < MAX_USERS; ++i )
  {
    if( sub[i] != NULL )
      strcat( strcat( strcat( buffer, "~~> "), sub[i]), ",\n");
    else
      break;
  }

  return buffer;
}

char* get_available_subscriptions()
{
  bzero(buffer, 512);                     // Store all available subs in buffer
  char** sub = current_user.subs;         // Pointer to subscriptions
  int already_subbed = 1;                 // Flag to check if already subscribed

  int i = 0;
  int j = 0;
  for( i = 0; i < MAX_USERS; ++i )
  {
    already_subbed = 0;

    // Iterate through each user
    if( users[i].username == NULL )
      break;

    // Make sure to not list current user as subscribe-able
    if( (strncmp( users[i].username, current_user.username, strlen(current_user.username)) == 0 ) )
      continue;

    for( j = 0; j < MAX_USERS; ++j )
    {
      // Iterate through each sub
      if( sub[j] == NULL )
	break;

      // Only check for those who are not already subscribed
      if( strncmp( sub[j], users[i].username, strlen(users[i].username)) == 0)
	already_subbed = 1;

    }

    if( !already_subbed )
      strcat( strcat( strcat( buffer, "~~> "), users[i].username), ",\n");

  }

  return buffer;
}

user subscribe_to()
{
  // If user entered valid username, add to subs
  user user_to_sub = get_user( buffer );

  printf("in subscribe_to after get_user\n");
  int i;
  for( i = 0; i < MAX_USERS; ++i )
  {
    if( user_to_sub.subs[i] == NULL )
    {
      printf("NULL Sub STRING\n");
      strcpy( user_to_sub.subs[i], buffer );
      return user_to_sub;
    }
    
  }
  
  return create_user(NULL, NULL, -1);
}

user unsubscribe_to()
{
  // If user entered valid username, add to subs
  user user_to_unsub = current_user;

  int i;
  for( i = 0; i < MAX_USERS; ++i )
  {
    if( (strncmp( user_to_unsub.subs[i], buffer, strlen(user_to_unsub.subs[i]) ) == 0)  )
    {
      user_to_unsub.subs[i] = '\0';
      return user_to_unsub;
    }
  }

  return create_user(NULL, NULL, -1);
}

void handle_subscriptions()
{
  char* main_msg = "============================\n CS164 Twitter Clone - Subscriptions \n============================\n0. Back\n1. Subscribe to\n2. Unsubscribe from.\n> ";
  
  while( current_menu != 0 )
  {
    n = write( newsockfd, main_msg, strlen(main_msg) );
    if( n < 0 ) error("ERROR writing to socket");
    
    // Read input from socket
    get_menu_input();
    

    if( current_menu == 1 || current_menu == 2  ) // Subscribe or unsubscribe
    {
      // Subscribe
      if( current_menu == 1)
      {
	char* msg = "\nYou may subscribe to the following: \n";
	// Since function returns pointer to buffer, which we are using right now, strcat will crash
	// if we append buffer to buffer! Temporary fix right now is to copy to a temp array
	char* msg2 = get_available_subscriptions();
	char msg4[512];
	strcpy( msg4, msg2 );
	char* msg3 = "\nEnter the username of who you wish to subscribe to, or 0 to cancel:\n> ";
	
	// Construct full message to send to user
	bzero(buffer, 512);
	strcat( buffer, msg );
	strcat( buffer, msg4 ); // temp array instead of msg2
	strcat( buffer, msg3 );
	
	n = write( newsockfd, buffer, strlen(buffer) );
	if( n < 0 ) error( "ERROR writing to socket");

	// Get input and place into buffer
	get_input();

	// Subscribe to selected user entered in buffer
	subscribe_to();

      }
      else if( current_menu == 2)
      {
	const char* msg = "You may unsubscribe from your current subs listed below: \n";
	char * msg2 = get_current_subscriptions();
	char msg3[512];
	char* msg4 = "\nEnter the username of who you wish to unsubscribe, or 0 to cancel:\n> ";
	strcat( msg3, msg2 );
	bzero(buffer, 512);
	strcat( strcat( strcat( buffer, msg ), msg3), msg4 );

	n = write( newsockfd, buffer, strlen(buffer) );
	if( n < 0 ) error( "ERROR writing to socket");
	
	// Get input
	get_input();

	// Subscribe to selected user entered in buffer
	unsubscribe_to();
      }
      
      
    }
  }
}


void handle_post_message()
{
  char* main_msg = "====================\n CS164 Twitter Clone - Post a Message to Subscriptions \n====================\n0. Back\n> ";
  
  while( current_menu != 0 )
  {
    
    n = write( newsockfd, main_msg, strlen(main_msg) );
    if( n < 0 ) error("ERROR writing to socket");
    
    
    // Read input from socket
    get_menu_input();
    
  }
  
}


void handle_hashtags()
{
  char* main_msg = "====================\n CS164 Twitter Clone - Hashtags Trending  \n====================\n0. Back\n";
  
  while( current_menu != 0 )
  {
    
    n = write( newsockfd, main_msg, strlen(main_msg) );
    if( n < 0 ) error("ERROR writing to socket");
    
    // Read input from socket
    get_menu_input();
  }
  
}
