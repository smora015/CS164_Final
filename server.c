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
  //struct sigaction sa;
  //sa.sa_handler = &handle_signal;

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
  listen(sockfd,6);                           
  clilen = sizeof(cli_addr);

  // Set up memory allocation, hard coded users, etc
  init_data();

  // Start receiving messages
  printf("Successfully binded to hostname/port.\n" );
  pid_t pid = 0;
  for(;;)
  {
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    // Socket failed to accept to client
    if (newsockfd < 0) 
      error("ERROR on accept");


    printf("Accepted port! With socket %d\n", newsockfd);
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
      
    }
    else if(pid == 0) // Child/Client process
    {
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
	  current_user->online = 0;

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
  bzero( new_user.username, MAX_LENGTH );
  bzero( new_user.password, MAX_LENGTH*2 );
  strncpy(new_user.username, username, strlen(username) );
  strncpy(new_user.password, password, strlen(password) );
  new_user.sockfd = mmap(NULL, sizeof * new_user.sockfd , PROT_READ | PROT_WRITE, 
       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  *new_user.sockfd = sockfd;
  new_user.message_count = 0;
  new_user.online = 0;

  // Format strings
  int i;
  for( i = 0; i < MAX_USERS; ++i )
    new_user.subs[i][0] = 0;

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

  messages_received = mmap(NULL, sizeof * messages_received, PROT_READ | PROT_WRITE, 
       MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  // Hard code 3 users
  user tom = create_user( "tom", "tom_password", -1);
  user chris = create_user( "chris", "chris_password", -1);
  user sara  = create_user( "sara", "sara_password", -1);

  users[0] = tom;
  users[1] = chris;
  users[2] = sara;
  users[3] = create_user( "", "", -1 );
  users[4] = create_user( "", "", -1 );

  // Initialize any counters or flags
  *messages_received = 0;
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
      if( strlen(users[i].username) == 0 )
	continue;

      // Compare username entered with username in list, providing the lenght of the username in the list.
      if( (strncmp(username, users[i].username, strlen(users[i].username) ) == 0) &&
	  (strncmp(password, users[i].password, strlen(users[i].password) ) == 0) ) 
      {
	found = 1; // Set found flag to true
	*users[i].sockfd = newsockfd; // Add current socket associated to user
	users[i].online = 1;          // Set online flag to 1

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


void handle_diagnostics()
{
  printf("Current user: %s, sockfd: %d \n", current_user->username, *(current_user->sockfd) );

  int i;
  for( i = 0; i < MAX_USERS; ++i)
  {
    if( strlen( users[i].username ) != 0 )
      printf("User %d: username: %s sockfd %d\n", i, users[i].username, *(users[i].sockfd) );
  }

  printf("Total messages received: %d\n", *messages_received );
  n = write( newsockfd, "", strlen("") );
  get_menu_input();
}



void handle_menu()
{
  int n;

  if( current_user->message_count > 0 )
  {
    // View realtime messages
    view_messages( 1 );
  }


  // Handle the rest of the menu
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
  else if( current_menu == 6)
  {
    handle_diagnostics();
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
      view_messages( 0 );
    }
    
    // Read input from socket
    get_menu_input();
    
  }
  
}

char* get_current_subscriptions()
{
  bzero(buffer, 512); // Store all available subs in buffer
  char** sub;         // Pointer to subscriptions

  int i;
  for( i = 0; i < MAX_USERS; ++i )
  {
    if( strlen(current_user->subs[i]) != 0 )
    //if( sub[i] != NULL )
      strcat( strcat( strcat( buffer, "~~> "), current_user->subs[i]), ",\n");
    //else break;
  }

  return buffer;
}

char* get_available_subscriptions()
{
  bzero(buffer, 512);                     // Store all available subs in buffer
  int already_subbed = 1;                 // Flag to check if already subscribed

  int i = 0;
  int j = 0;
  for( i = 0; i < MAX_USERS; ++i )
  {
    already_subbed = 0;

    // Iterate through each user
    if( strlen(users[i].username) == 0  )
      continue;

    // Make sure to not list current user as subscribe-able
    if( (strncmp( users[i].username, current_user->username, strlen(current_user->username)) == 0 ) )
      continue;

    for( j = 0; j < MAX_USERS; ++j )
    {
      // Iterate through each sub
      if( strlen(current_user->subs[j]) == 0 )
	continue;

      // Only check for those who are not already subscribed
      if( strncmp( current_user->subs[j], users[i].username, strlen(users[i].username)) == 0)
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
  if( strlen(user_to_sub.username) != 0 )
  {
    // Iterate through current_user's subs
    for( i = 0; i < MAX_USERS; ++i )
    {
      if( strlen(current_user->subs[i]) == 0 )
      {
	strncpy( current_user->subs[i], user_to_sub.username, strlen(user_to_sub.username) );
	//current_user->subs[i] = user_to_sub.username;
	return user_to_sub;
      }
    
    }
  }
  return create_user("", "", -1);
}

user unsubscribe_to()
{
  // If user entered valid username, add to subs
  user user_to_unsub = get_user( buffer );

  int i;

  if( strlen(user_to_unsub.username) != 0 )
  {
    // Iterate through all of user's subs
    for( i = 0; i < MAX_USERS; ++i )
    {
      // If we've found user's sub to remove, then proceed
      if( (strncmp( current_user->subs[i], user_to_unsub.username, strlen(current_user->subs[i]) ) == 0)  )
      {


	// If we're not the last possible user, then make sure we don't cut off users after user_to_unsub
	if( (i+1) < MAX_USERS )
	{
	  // If there's a sub ahead of user_to_unsub in the array, move back up
	  if( strlen(current_user->subs[i+1]) != 0 )
	  {
	    int j;
	    for( j = i; j < MAX_USERS-1; ++j )
	    {
	      if( strlen(current_user->subs[j+1]) == 0 )
	      {
		current_user->subs[j][0] = 0;
		break;
	      }
	      else
		strncpy( current_user->subs[j], current_user->subs[j+1], strlen(current_user->subs[j+1]) );
		//current_user->subs[j] = current_user->subs[j+1];
	    }
	  }
	  // If there isn't a sub ahead, just make user_to_unsub's location NULL
	  else
	    current_user->subs[i][0] = 0;
	}
	// If we're the last possible user, just make null
	else
	  current_user->subs[i][0] = 0;

	return user_to_unsub;


      }
    }
  }
  return create_user("", "", -1);
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


void view_messages( int real_time )
{
  if( real_time == 1 )
  {
    int real_time_flag = 0; // Set to 1 if at least one message was sent in realtime
    int j;
    bzero(buffer, 512 );
    char * mainmsg = "You received a message!\n";
    strcat( buffer, mainmsg );

    int count = current_user->message_count;
    // Iterate through all messages
    for( j = 0; j < count; ++j )
      {
	if( current_user->messages[j].offline == 0 )
	  {
	    strcat( strcat( buffer, current_user->messages[j].message ), "\n" );
	    --current_user->message_count;

	    real_time_flag = 1;
	  }
      }
    strcat( buffer, "> " );

    if( real_time_flag == 1 )
    {
      // Send to user
      n = write( newsockfd, buffer, strlen(buffer) );
      if( n < 0 )
	error("error writing to socket");

      // Get menu input
      get_menu_input();
    }
  }
  else
  {
    int j;
    bzero(buffer, 512 );
    char * mainmsg = "You received the following messages:\n";
    strcat( buffer, mainmsg );

    int count = current_user->message_count;
    // Iterate through all messages
    for( j = 0; j < count; ++j )
      {
	if( current_user->messages[j].offline == 1 )
	  {
	    strcat( strcat( buffer, current_user->messages[j].message ), "\n" );
	    --current_user->message_count;
	  }
      }
    strcat( buffer, "> " );

    // Send to user
    n = write( newsockfd, buffer, strlen(buffer) );
    if( n < 0 )
      error("error writing to socket");

    // Get menu input
    get_menu_input();

  }
}

void post_message()
{
  // Create message from buffer
  char message1[256];
  bzero( message1, 255 );
  strncpy( buffer, buffer, strlen( buffer ) );
  strcat( strcat( strcat( strcat( strcat( message1, "\n[User "), current_user->username), "] - "), buffer ), "\n");



  // Find all users subscribed to current_user
  int i, j;
  for( i = 0; i < MAX_USERS; ++i )
  {
    // Skip current user
    if( (strncmp(users[i].username, current_user->username, strlen(current_user->username)) == 0) )
      continue;
	  
    // Traverse through user's subscription, checking to make sure 
    for( j = 0; j < MAX_USERS; ++j )
    {
      // If user is found to be subscribed to current user, send message to them
      if( (strncmp(users[i].subs[j], current_user->username, strlen(current_user->username)) == 0) )
      {
	printf("Sending message to %s\n", users[i].username );
	message new_message;
	strncpy( new_message.from, current_user->username, strlen( current_user->username ) );
	strncpy( new_message.message, message1, strlen( message1 ) );

	if( users[i].online == 0 )
	  new_message.offline = 1;
	else
	  new_message.offline = 0;

	users[i].messages[ users[i].message_count ] = new_message;
	++users[i].message_count;

	// Increment server's message count
	++(*messages_received);

	// Search for any hashtags within the message
	char* ht = strstr( buffer, "#" );
	if( ht != NULL )
	{
	  printf("found hashtag!\n");
	  char ht_msg[30];
	  
	  char* ptr = ht;
	  ++ptr; // Skip the '#'
	  int i = 0;
	  while( (*ptr >= 33) && (*ptr <= 122)  )
	  {
	    // While pointer is a valid char, add to hashtag for user
	    current_user->hashtags[ current_user->hashtag_count ][i] = *ptr;
	    ++i;
	    ++ptr;
	  }
	  current_user->hashtags[ current_user->hashtag_count ][i] = '\0';  // Append 0 to signal end of string
	  ++current_user->hashtag_count; // Increment current user's hashtag count
	}

      }
	
    }
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


void search_hashtags()
{
  // Traverse through user's hashtags
  bzero(buffer, 512);
  int i, j;

  strcat( buffer, "Found the following hashtags from friends:\n" );
  for( j = 0; j < MAX_USERS; ++j )
  {
    if( (strncmp( users[j].username, current_user->username, strlen(users[j].username) ) == 0) )
      continue;

    for( i = 0; i < users[j].hashtag_count; ++i )
    {
      if( strlen( users[j].hashtags[i]) > 0 )
      {
	strcat( strcat( strcat( strcat( buffer, users[i].username ), " - " ), users[j].hashtags[i] ), "\n");
      }
    }
  }
}


void handle_hashtags()
{
  char* main_msg = "====================\n CS164 Twitter Clone - Hashtags Trending  \n====================\n0. Back\n1. Search all friend's hastags\n> ";
  
  while( current_menu != 0 )
  {
    n = write( newsockfd, main_msg, strlen(main_msg) );
    if( n < 0 ) error("ERROR writing to socket");
    
    // Read input from socket
    get_menu_input();

    if( current_menu == 1) 
    {
      // Place all hashtags found in buffer and output
      search_hashtags(); 

      n = write( newsockfd, buffer, strlen( buffer ) );
      if( n < 0 )
	error("error writing to socket");

      get_menu_input();
    }
  }
  
}
