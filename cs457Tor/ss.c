#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include "awget.h"

#define MYPORT "61723"
#define MAXDATASIZE 144 // max bytes we can get at once
#define NUM_THREADS 5 // max threads we support

// struct for passing multiple arguments to a thread
typedef struct {
 int thread_id;
 int newfd;
 awget_t awgetData;
} thread_data_t;


//
// display help and exit
//
void help() {
  printf("Usage: ./ss [-p port]\n");
  exit(0);
}

//
// verify ip and port are sound
//
void verifyInput(char *port) {
  if (port == NULL) {
    return;
  }
	for (int i = 0; i < strlen(port); ++i) {
    if (port[i] >= '0' && port[i] <= '9') {
			// OK!
		} else {
			printf("ERROR: port must consist of numbers, got '%s'\n", port);
			exit(-1);
		}
	}
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void readSteppingStoneFile(char *chainfile, awget_t *meta)
{
  FILE *fp;
  char *mode = "r";
  fp = fopen(chainfile, mode);
  if (fp == NULL) {
    printf("Cannot open file %s\n", chainfile);
    exit(1);
  }
  
  int numSS;
  fscanf(fp, "%d", &numSS);
  meta->numStones = numSS;

  printf("chainlist is\n");
  char ssAddr[IP_SIZE];
  char ssPort[PORT_SIZE];
  memset(&ssAddr, 0, sizeof(ssAddr));
  memset(&ssPort, 0, sizeof(ssPort));
  int i = 0;
  while (fscanf(fp, "%s %s", ssAddr, ssPort) != EOF) {
    printf("  <%s, %s>\n", ssAddr, ssPort);
    ss_t ss;
    memcpy(&(ss.ip_addr), &ssAddr, sizeof(ssAddr));
    memcpy(&(ss.port), &ssPort, sizeof(ssPort));
    memcpy(&(meta->stones[i]), &ss, sizeof(ss));
    i++;
  }
}

int startServer(char *port)
{
  int sockfd; // server socket
	struct addrinfo hints; // relevant socket information
  struct addrinfo *res; // results of getaddrinfo (linked list)
  int yes = 1; // used in setsocketopt()
  int status; 

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE; // use my IP address

	if ((status = getaddrinfo(NULL, port, &hints, &res)) != 0) {
		printf("ERROR: startServer getaddrinfo failed\n");
		exit(1);
	}

	// create a socket
	if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		printf("ERROR: startServer socket failed\n");
		exit(1);
	}

  // lose the pesky "Address already in use" error message
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		printf("ERROR: startServer setsockopt failed\n");
		exit(1);
	}

  // bind the socket
	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		printf("ERROR: startServer bind failed\n");
		exit(1);
	}

  return sockfd;
}

void *doWork(void *threadarg)
{
//     if (chainlist empty)
//       system(wget)
//       send html packet to newfd
//       tear down connection and delete local copy
//     else
//       select next random stepping stone
//       serialize wgetData
//       socket,connect next_ss_fd
//       wait to receive html packet from next ss receive BLOCKS
//       send html packet to newfd
//       tear down connection and delete local copy
  thread_data_t *thread_data = (thread_data_t *)threadarg;
  awget_t data = (awget_t)thread_data->awgetData;
  printf("  Request: %s\n", data.url);

  if (data.numStones == 0) {
    printf("  chainlist is empty\n");

    // get filename for stdout
    char *start = NULL;
    char *c = data.url;
    for (int i = 0; i < URL_SIZE; i++) {
      if (*(c++) == '/') {
        start = c;
      }
    }
    if (start == NULL) {
      printf("ERROR: not able to decipher webpage name, did the URL have a file name?\n");
      exit(1);
    }
    char fname[URL_SIZE];
    strncpy(fname, start, (c-start));
    printf("  issuing wget for file %s\n..\n", fname);

    char command[1024];
    char filename[1024];
    sprintf(filename, "/tmp/sga_ss_thread_%d_webpage.html", thread_data->thread_id);
    char *tmpfile = filename;
    sprintf(command, "wget %s -qO %s", data.url, tmpfile);
    if (system(command) != 0) {
      printf("ERROR: system call '%s' failed\n", command);
      exit(1);
    }
    
    FILE *f = fopen(tmpfile, "rb");
    if (f == NULL) {
      printf("Cannot open file %s\n", tmpfile);
      exit(1);
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *string = (unsigned char*)malloc(fsize);
    memset(string, 0, fsize);
    fread(string, fsize, 1, f);
    fclose(f);

    unsigned char *html_packet = (unsigned char*)malloc(fsize);
    memset(html_packet, 0, fsize);
    memcpy(html_packet, string, fsize);

    free(string);

    printf("  File received\n");
    printf("  Relaying file ...\n");

    // first, send the size of html page coming down the pipe
    int sendsize = sizeof(uint32_t);
    uint32_t net_fsize = htonl(fsize);
    unsigned char *size_packet = (unsigned char*)malloc(sizeof(uint32_t));
    memset(size_packet, 0, sizeof(uint32_t));
    memcpy(size_packet, &net_fsize, sizeof(uint32_t));

    int rc = sendall(thread_data->newfd, size_packet, &sendsize);
    if (rc != 0) {
      printf("ERROR: failed to send html packet\n");
      exit(1);
    }
    free(size_packet);

    sleep(1);

    // now send the html page contents
    sendsize = fsize;
    rc = sendall(thread_data->newfd, html_packet, &sendsize);
    if (rc != 0) {
      printf("ERROR: failed to send html packet\n");
      exit(1);
    }
    if (remove(tmpfile) != 0) {
      printf("ERROR: failed to delete file '%s'\n", tmpfile);
      exit(1);
    }
    free(html_packet);
    printf("  Goodbye!\n");
  } else {
    printf("  chainlist is\n");
    for (int i = 0; i < data.numStones; i++) {
      printf("  <%s, %s>\n", data.stones[i].ip_addr, data.stones[i].port);
    }
    ss_t nextSS = selectRandomSteppingStone(&data);

    // Connect to first stepping stone
    int sockfd;
    struct addrinfo hints, *servinfo;
    int rv;
    //char server_ip[INET_ADDRSTRLEN];
    //struct sockaddr_storage;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; //AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = IPPROTO_TCP;//AI_PASSIVE;

    if ((rv = getaddrinfo(nextSS.ip_addr, nextSS.port, &hints, &servinfo)) != 0) {
      printf("ERROR: getaddrinfo failed\n");
      exit(1);
    }

    if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 0) {
      printf("ERROR: client socket failed\n");
      exit(1);
    }

    if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
      printf("ERROR: client connect failed\n");
      exit(1);
    }

    // Serialize the meta struct into a char array
    unsigned char *packet = serialize(&data);

    // Send meta data to first stepping stone
    int sendsize = AWGET_SIZE;
    int rc = sendall(sockfd, packet, &sendsize);
    if (rc != 0) {
      printf("ERROR: failed to send html packet\n");
      exit(1);
    }
    
    // Wait to receive the file
    printf("  waiting for file...\n..\n");
    unsigned char buffer[sizeof(uint32_t)];
    memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      printf("Connection closed.\n");
      exit(1);
    } else if (recv_bytes == -1) {
      printf("ERROR: ss recv failed\n");
      exit(1);
    } else {
      // wait for first packet with webpage size
      uint32_t net_fsize;
      memcpy(&net_fsize, buffer, sizeof(uint32_t));
      uint32_t fsize = ntohl(net_fsize);
      printf("incoming packet size %d\n", fsize);

      // receive webpage now
      int totalReceived = 0, received = 0;
      unsigned char *html_packet = (unsigned char*)malloc(fsize+1);
      while (totalReceived < fsize) {
        received = recv(sockfd, (html_packet+totalReceived), fsize, 0);
        totalReceived += received;
        if (received == 0) {
          printf("Connection closed.\n");
          exit(1);
        } else if (received == -1) {
          printf("ERROR: ss2 recv failed\n");
          fprintf(stderr, "ss2: %s\n", gai_strerror(received));
          exit(1);
        }
      }
      printf("  Relaying file...\n");

      // send html packet back to calling socket
      int sendsize = sizeof(uint32_t);
      unsigned char *size_packet = (unsigned char*)malloc(sizeof(uint32_t));
      memset(size_packet, 0, sizeof(uint32_t));
      memcpy(size_packet, &net_fsize, sizeof(uint32_t));

      int rc = sendall(thread_data->newfd, (unsigned char*)size_packet, &sendsize);
      if (rc != 0) {
        printf("ERROR: failed to send html packet\n");
        exit(1);
      }

      // now send the html page contents
      sendsize = fsize;
      rc = sendall(thread_data->newfd, (unsigned char*)html_packet, &sendsize);
      if (rc != 0) {
        printf("ERROR: failed to send html packet\n");
        exit(1);
      }
      free(html_packet);
      free(size_packet);
      printf("  Goodbye!\n");
    }
  }
  close(thread_data->newfd);
  free(threadarg);
  return 0;
}

//
// get the outside ip address of this host and print it
//
void printPrimaryIp(char *port)
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  const char* kGoogleDnsIp = "8.8.8.8";
  uint16_t kDnsPort = 53;
  struct sockaddr_in serv;
  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
  serv.sin_port = htons(kDnsPort);

  connect(sock, (struct sockaddr*) &serv, sizeof(serv));

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  getsockname(sock, (struct sockaddr*) &name, &namelen);

	char buffer[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));
	printf("ss <%s, %s>:\n", buffer, port);

  close(sock);
}

int main(int argc, char* argv[])
{
  char *port = NULL;
  srand(time(NULL));
  
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-h") == 0) {
      help();
    } else if (strcmp(argv[i], "-p") == 0) {
      port = argv[++i];
    } else {
      help();
    }
  }

  if (port != NULL) {
    verifyInput(port);
  } else {
    port = MYPORT;
  }
  printPrimaryIp(port);

  int sockfd = startServer(port);
  int newfd; // socket to incoming connection
  int thread_id = -1;

  for (;;) {
    // set socket to listen
	  if (listen(sockfd, 10) < 0) {
	  	printf("ERROR: sockfd listen failed\n");
	  	exit(1);
	  }
    // accept new connection
    struct sockaddr_storage their_addr;
	  socklen_t addr_size = sizeof(their_addr);
	  if ((newfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size)) < 0) {
	  	printf("ERROR: sockfd accept failed\n");
	  	exit(1);
	  } else {
      // get new connection's packet
      unsigned char *buffer = (unsigned char*)malloc(AWGET_SIZE);
		  memset(buffer, 0, AWGET_SIZE);
      int recv_bytes = recv(newfd, buffer, AWGET_SIZE, 0);
      if (recv_bytes == 0) {
        printf("Socket session closed.\n");
        exit(0);
      } else if (recv_bytes == -1) {
        printf("ERROR: sockfd recv failed\n");
        exit(1);
      } else {
        awget_t data;
        deserialize(&data, buffer);
        thread_id++;
        // the pthread_t malloc leaks memory since it is never cleaned up
        // it's only 8 bytes per thread though so not a big deal at this time
        pthread_t *thread = (pthread_t *)malloc(sizeof(pthread_t));
        thread_data_t *thread_data = (thread_data_t *)malloc(sizeof(thread_data_t));
        thread_data->newfd = newfd;
        thread_data->thread_id = thread_id;
        thread_data->awgetData = data;
        if (pthread_create(thread, NULL, doWork, (void *) thread_data)) {
          printf("ERROR: could not create thread\n");
          exit(1);
        }
        free(buffer);
      }
    }
  } // for (;;)

  return 0;
}

