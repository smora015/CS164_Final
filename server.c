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


user create_user( char* username, char* password, int sockfd)
{
  user new_user;
  new_user.username = username;
  new_user.password = password;
  new_user.sockfd = sockfd;
  new_user.message_count = 0;
  new_user.online = 0;

  return new_user;
}

user get_user( char* username )
{
  int i;
  char cmp[50];
  strcpy( cmp, username );

  for( i = 0; i < MAX_USERS; ++i )
  {
    if( users[i].username == NULL )
      break;

    if( strncmp( users[i].username, cmp, strlen(users[i].username)) == 0 )
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


      if( users[i].online == 1 )
	printf("[Status] %s is also online!\n", users[i].username);

      // Compare username entered with username in list, providing the lenght of the username in the list.
      if( (strncmp(username, users[i].username, strlen(users[i].username) ) == 0) &&
	  (strncmp(password, users[i].password, strlen(users[i].password) ) == 0) ) 
      {
	found = 1; // Set found flag to true
	users[i].sockfd = newsockfd; // Add current socket associated to user
	users[i].online = 1;         // Set online flag to 1

	// Contacenate message
	strcat( strcat(ss, ss1), users[i].username );
	char mc[20];
	snprintf(mc, 20, "%d", users[i].message_count);
	strcat( strcat( strcat( ss, ss2 ), mc ), ss3);

	// Set current_user in this thread to the user who just logged in
	current_user = &users[i]; 
	printf("[User %s] - Is now online.\n", current_user->username);

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
    if( current_user->messages[0].message == NULL )
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

  // Get the subs of the current user
  sub = current_user->subs;
  int i;
  for( i = 0; i < MAX_USERS; ++i )
  {
    if( sub[i] != NULL )
      strcat( strcat( strcat( buffer, "~~> "), sub[i]), ",\n");
    else break;
  }

  return buffer;
}

char* get_available_subscriptions()
{
  bzero(buffer, 512);                     // Store all available subs in buffer
  char** sub = current_user->subs;        // Pointer to subscriptions
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
    if( (strncmp( users[i].username, current_user->username, strlen(current_user->username)) == 0 ) )
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
  int i;

  // Make sure input is a valid user
  if( user_to_sub.username != NULL )
  {
    // Iterate through current_user's subs
    for( i = 0; i < MAX_USERS; ++i )
    {
	if( current_user->subs[i] == NULL )
	{
	  current_user->subs[i] = user_to_sub.username;
	  return user_to_sub;
	}
    
    }
  }
  return create_user(NULL, NULL, -1);
}

user unsubscribe_to()
{
  // If user entered valid username, add to subs
  user user_to_unsub = get_user( buffer );

  int i;

  if( user_to_unsub.username != NULL )
  {
    for( i = 0; i < MAX_USERS; ++i )
    {
      if( (strncmp( current_user->subs[i], user_to_unsub.username, strlen(current_user->subs[i]) ) == 0)  )
      {
	// If we're not the last possible user, then make sure we don't cut off users after user_to_unsub
	if( (i+1) < MAX_USERS )
	{
	  // If there's a sub ahead of user_to_unsub in the array, move back up
	  if( current_user->subs[i+1] != NULL )
	  {
	    int j;
	    for( j = i; j < MAX_USERS-1; ++j )
	    {
	      if( current_user->subs[j+1] == NULL )
	      {
		current_user->subs[j] = NULL;
		break;
	      }
	      else
		current_user->subs[j] = current_user->subs[j+1];
	    }
	  }
	  // If there isn't a sub ahead, just make user_to_unsub's location NULL
	  else
	    current_user->subs[i] = NULL;
	}
	// If we're the last possible user, just make null
	else
	  current_user->subs[i] = NULL;

	return user_to_unsub;
      }
    }
  }
  return create_user(NULL, NULL, -1);
}

void handle_subscriptions()
{
  char* main_msg = "============================\n CS164 Twitter Clone - Subscriptions \n============================\n0. Back\n1. Subscribe to\n2. Unsubscribe from.\n> ";

  n = write( newsockfd, main_msg, strlen(main_msg) );
  if( n < 0 ) error("ERROR writing to socket");
  
  while( current_menu != 0 )
  {
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
	char* msg3 = ( (strlen(msg2) > 0) ? "\nEnter the username of who you wish to subscribe to, or 0 to cancel:\n> " : "There are no users to subscribe to! Press enter to continue.\n");
	
	// Construct full message to send to user
	bzero( buffer, 512 );
	strcat( buffer, msg );
	strcat( buffer, msg4 ); // temp array instead of msg2
	strcat( buffer, msg3 );
	
	n = write( newsockfd, buffer, strlen(buffer) );
	if( n < 0 ) error( "ERROR writing to socket");

	// Get input and place into buffer
	get_input();

	// Subscribe to selected user entered in buffer
        user subbed = subscribe_to();

	bzero( buffer, 512 );	
	if( subbed.username != NULL )
	{
	  snprintf( buffer, 512, "You are now subscribed to %s's posts!\n\n", subbed.username );
	  strcat( buffer, main_msg );
	}
	else
	  strcat( strcat( buffer, "Cancelled / user not found! \n\n" ), main_msg );

	n = write( newsockfd, buffer, strlen( buffer ) );
	if( n < 0 ) error("ERROR writing to socket");
	
	
      }
      else if( current_menu == 2)
      {
	const char* msg = "You may unsubscribe from your current subs listed below: \n";
	char * msg2 = get_current_subscriptions();
	char msg3[512];
	char* msg4 = ( (strlen(msg2) > 0) ? "\nEnter the username of who you wish to unsubscribe, or 0 to cancel:\n> ": "There are no users for you to unsubscribe from. Press enter to continue.\n") ;
	strcpy( msg3, msg2 );

	// Display users to unsub from
	bzero( buffer, 512 );
	strcat( strcat( strcat( buffer, msg ), msg3), msg4 );
	n = write( newsockfd, buffer, strlen(buffer) );
	if( n < 0 ) error( "ERROR writing to socket");
	
	// Get input
	get_input();

	// Subscribe to selected user entered in buffer
	user unsubbed = unsubscribe_to();

	// Display new status
	bzero( buffer, 512 );	
	if( unsubbed.username != NULL )
	{
	  snprintf( buffer, 512, "You have unsubscribed from %s's posts!\n\n", unsubbed.username );
	  strcat( buffer, main_msg );
	}
	else
	  strcat( strcat( buffer, "Cancelled / user not found! \n\n" ), main_msg );

	n = write( newsockfd, buffer, strlen(buffer) );
	if( n < 0 ) error("ERROR writing to socket");
      }
      
    }
  }
}

void post_message()
{
  int subscribed = 0; // Flag to check for any valid subscribers
  int i, j;
  for( i = 0; i < MAX_USERS; ++i )
  {
    // End of valid users
    if( users[i].username == NULL )
      break;

    if( users[i].subs[0] != NULL )
    {
      // Traverse through all users who's subs include current_user
      for( j = 0; j < MAX_USERS; ++j )
      {
	// End of valid subs
	if( users[i].subs[j] == NULL )
	{
	  break;
	}

	// If user is subscribed to current_user
	if( (strncmp(users[i].subs[j], current_user->username, strlen(current_user->username)) == 0 ) )
	{
	  // Set flag to signal that current_user does have people following him/her
	  subscribed = 1;
	  
	  // Send a message in realtime if they are online
	  if( users[i].online == 1 )
	  {
	    printf("[Status] - Post Message: Sending message to %s in realtime\n", users[i].username );
	  }
	  // Otherwise send message offline
	  else
	  {
	    printf("Sending message to %s offline\n", users[i].username );
	  }
	}
      } 
    }
    
    else
      printf(" who does NOT have subscriptions \n");

  }

}

void handle_post_message()
{
  char* main_msg = "====================\n CS164 Twitter Clone - Post a Message to Subscriptions \n====================\n0. Back\n1. Post message to users following you\n> ";
  
  while( current_menu != 0 )
  {    
    // Display menu
    n = write( newsockfd, main_msg, strlen(main_msg) );
    if( n < 0 ) error("ERROR writing to socket");
    
    // Read 
    get_menu_input();
    
    if( current_menu == 1 )
    {
      // Display send message menu
      char* msg = "What would you like to send? (Max 140 characters) Or press enter to go back.\n> ";
      n = write( newsockfd, msg, strlen(main_msg) );
      if( n < 0 ) error("ERROR writing to socket");
      
      // Read message into buffer
      get_input();

      // Send message to users
      post_message();
    }
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
