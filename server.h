#ifndef __SERVER_H__
#define __SERVER_H__

// Macros
#define MAX_USERS 5
#define MAX_MESSAGES 255

// Declare structs
typedef struct messages_struct {
  char* from;
  char* to; // Only used for private messages
  char* message;
} message;

typedef struct user_struct {
  char* username;
  char* password;

  int sockfd;        // The current socket the user is associated to

  char** subs;       // Keeps track of current subscriptions
  message* messages; // Keeps track of sent but not delivered messages
  int message_count; // The number of messages
} user;

// Declare socket descriptors
int sockfd;            // Socket file descriptor
int newsockfd;         // New socket file descriptor

char buffer[512];      // Buffer to hold messages
int n = 0;             // Used to read/write from/to socket

// Declare server variables
user* users;           // List of total users
user* users_online;    // List of currently online users
user* current_user;    // The current user logged in
int current_menu;      // Corresponds to what menu the user is in
int messages_received; // Keeps track of number of messages received

// Error handling functions
void error(const char *msg);
void handle_signal( int signal );

// Initialization functions
user create_user( char* username, char* password, int sockfd, message* messages, char** subs);
user* get_current_user( int sockfd );
user* get_user( char* username );
void init_data();
int authenticate_user( int* sockfd );

// Interface functions
void get_input();
void handle_menu();
void handle_offline_messages();
char* get_available_subscriptions();
void handle_subscriptions();
void handle_post_message();
void handle_hashtags();

#endif /* __SERVER_H__ */

/*   Server Side:

  DONE   1. Validate a user login (3-5 hard coded)
  2. Maintain a list of user's subscriptions to other users, and allow them to change it
  3. Receive messages and redistribute in real time
  4. Store messages sent (not delivered) if the subscribers were offline.
  5. Implement "messagecount" in order to display the number of messages received since the server was activated
*/

/*    Client Side Specifications:

   DONE   1. Prompt the user for their username and password
   DONE   2. Provide a welcome message that displays number of new messages
   3. Provide a menu for the user to select valid options. Should be a way to navigate back
   HALF DONE   4. Menu option: See Offline Messages  [Needs to display if theres > 0 msgs]
   5. Menu option: Edit Subscriptions
   6. Menu option: Post a message
   DONE   7. Menu option: Logout
   8. Display messages in realtime
   9. Menu option: hashtag search (get last 10 hashtags generated by any of the user's subscriptions) */
