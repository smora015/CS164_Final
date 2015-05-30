#ifndef __SERVER_H__
#define __SERVER_H__


// Declare structs
typedef struct messages_struct {
  char* from;
  char* to;
  char* message;
} message;

typedef struct user_struct {
  char* username;
  char* password;
  
  message* messages;
} user;


// Declare socket descriptors
int sockfd;            // Socket file descriptor
int newsockfd;         // New socket file descriptor

// Server variables
int messagecount;      // Keeps track of number of messages received

// Declare functions
void error(const char *msg);
void handle_signal( int signal );


#endif /* __SERVER_H__ */


/*
  Server Side:

  1. Validate a user login (3-5 hard coded)
  2. Maintain a list of user's subscriptions to other users, and allow them to change it
  3. Receive messages and redistribute in real time
  4. Store messages sent (not delivered) if the subscribers were offline.
  5. Implement "messagecount" in order to display the number of messages received since the server was activated

*/
