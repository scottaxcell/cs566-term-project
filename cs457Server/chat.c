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

#define MYPORT "61723"
#define MAXDATASIZE 144 // max bytes we can get at once

//
// display help and exit
//
void help() {
	printf("Usage: ./chat [-p <port> -s <ip address>]\n");
  exit(0);
}

//
// verify ip and port are sound
//
void verifyInput(char *ip_addr, char *port) {
	if (!ip_addr || !port) {
		printf("ERROR: missing parameters\n");
		help();
	}

	for (int i = 0; i < strlen(ip_addr); ++i) {
    if ((ip_addr[i] >= '0' && ip_addr[i] <= '9') || ip_addr[i] == '.') {
			// OK!
		} else {
			printf("ERROR: ip address must consist of numbers and periods, got '%s'\n", ip_addr);
			exit(-1);
		}
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

//
// get the outside ip address of this host and print it
//
void getPrimaryIp()
{
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  const char* kGoogleDnsIp = "8.8.8.8";
  uint16_t kDnsPort = 53;
  struct sockaddr_in serv;
  memset(&serv, 0, sizeof(serv));
  serv.sin_family = AF_INET;
  serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
  serv.sin_port = htons(kDnsPort);

  int err = connect(sock, (struct sockaddr*) &serv, sizeof(serv));

  struct sockaddr_in name;
  socklen_t namelen = sizeof(name);
  err = getsockname(sock, (struct sockaddr*) &name, &namelen);

	char buffer[INET_ADDRSTRLEN];
  const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer));
	printf("Welcome to Chat!\n");
	printf("Waiting for a connection on %s port %s\n", buffer, MYPORT);

  close(sock);
}

void server() {
	int sockfd, newfd; // listen on sockfd, new connection on newfd
	struct addrinfo hints, *res;
	struct sockaddr_storage their_addr;
	socklen_t addr_size;
	int rv;
	int yes = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; //AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE; // use my IP address

	if ((rv = getaddrinfo(NULL, MYPORT, &hints, &res)) != 0) {
		printf("ERROR: getaddrinfo failed\n");
		exit(1);
	}

	// make a socket, bind it, listen on it
	if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		printf("ERROR: socket failed\n");
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		printf("ERROR: setsockopt failed\n");
		exit(1);
	}

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		printf("ERROR: bind failed\n");
		exit(1);
	}

	if (listen(sockfd, 10) < 0) {
		printf("ERROR: listen failed\n");
		exit(1);
	}
	
	getPrimaryIp();

	// now accept an incoming connection
	addr_size = sizeof(their_addr);
	if ((newfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size)) < 0) {
		printf("ERROR: listen accept\n");
		exit(1);
	}

	printf("Found a friend! You receive first.\n");

  char buffer[MAXDATASIZE];
  while (1) {
		memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(newfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      printf("Chat session closed.\n");
      exit(0);
    } else if (recv_bytes == -1) {
      printf("ERROR: server recv failed\n");
      exit(1);
    } else {
			uint16_t recv_version = ntohs(buffer[0] | buffer[1] << 8);
			uint16_t recv_size = ntohs(buffer[2] | buffer[3] << 8);

      printf("Friend: ");
			for (int i = 4; i <= (recv_size+4); i++) {
				printf("%c", buffer[i]);
			}
      printf("\nYou: ");

      char msg[140];
			memset(&msg[0], 0, sizeof(msg));
			fgets(msg, 200, stdin);
			while (strlen(msg) > 140) {
        printf("Error: Input too long.\nYou: ");
			  memset(&msg[0], 0, sizeof(msg));
			  fgets(msg, 200, stdin);
			}
			size_t ln = strlen(msg) - 1;
			if (msg[ln] == '\n') {
			  msg[ln] = '\0';
			}

			uint16_t version = htons(457);
			uint16_t msgsize = htons(strlen(msg));
			
			char packet[144];
			memset(&packet[0], 0, sizeof(packet));
		  memcpy ( &packet[0], &version, sizeof(version) );
		  memcpy ( &packet[2], &msgsize, sizeof(msgsize) );
		  strncpy ( &packet[4], msg, strlen(msg) );

      int bytes_sent = -1, len = strlen(msg)+4;
      while (bytes_sent != len) {
        bytes_sent = send(newfd, &packet, len, 0);
      }
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

void client(char *ip_addr, char *port) {
	printf("Connecting to server... ");

	int sockfd, numbytes;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char server_ip[INET_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; //AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ip_addr, port, &hints, &servinfo)) != 0) {
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

	inet_ntop(servinfo->ai_family, get_in_addr((struct sockaddr *)servinfo->ai_addr), server_ip, sizeof(server_ip));
	printf("Connected!\n");
	printf("Connected to a friend! You send first.\n");

  printf("You: ");
  char msg[140];
	memset(&msg[0], 0, sizeof(msg));
	fgets(msg, 200, stdin);
	while (strlen(msg) > 140) {
    printf("Error: Input too long.\nYou: ");
	  memset(&msg[0], 0, sizeof(msg));
	  fgets(msg, 200, stdin);
	}
	size_t ln = strlen(msg) - 1;
	if (msg[ln] == '\n') {
	  msg[ln] = '\0';
	}

	uint16_t version = htons(457);
	uint16_t msgsize = htons(strlen(msg));

	char packet[144];
	memset(&packet[0], 0, sizeof(packet));
  memcpy ( &packet[0], &version, sizeof(version) );
  memcpy ( &packet[2], &msgsize, sizeof(msgsize) );
  strncpy ( &packet[4], msg, strlen(msg) );

  int bytes_sent = -1, len = strlen(msg)+4;
  while (bytes_sent != len) {
    bytes_sent = send(sockfd, &packet, len, 0);
  }

  char buffer[MAXDATASIZE];
  while (1) {
		memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      printf("Chat session closed.\n");
      exit(0);
    } else if (recv_bytes == -1) {
      printf("ERROR: server recv failed\n");
      exit(1);
    } else {
			uint16_t recv_version = ntohs(buffer[0] | buffer[1] << 8);
			uint16_t recv_size = ntohs(buffer[2] | buffer[3] << 8);

      printf("Friend: ");
			for (int i = 4; i <= (recv_size+4); i++) {
				printf("%c", buffer[i]);
			}
      printf("\nYou: ");

      char msg[140];
			memset(&msg[0], 0, sizeof(msg));
			fgets(msg, 200, stdin);
			while (strlen(msg) > 140) {
        printf("Error: Input too long.\nYou: ");
			  memset(&msg[0], 0, sizeof(msg));
			  fgets(msg, 200, stdin);
			}
			size_t ln = strlen(msg) - 1;
			if (msg[ln] == '\n') {
			  msg[ln] = '\0';
			}

			uint16_t version = htons(457);
			uint16_t msgsize = htons(strlen(msg));
			
			char packet[144];
			memset(&packet[0], 0, sizeof(packet));
		  memcpy ( &packet[0], &version, sizeof(version) );
		  memcpy ( &packet[2], &msgsize, sizeof(msgsize) );
		  strncpy ( &packet[4], msg, strlen(msg) );

      int bytes_sent = -1, len = strlen(msg)+4;
      while (bytes_sent != len) {
        bytes_sent = send(sockfd, &packet, len, 0);
      }
    }
  }
}


int main(int argc, char* argv[]) {
	if (argc <= 1) {
		server();
	}
	else if (argc == 2) {
		help();
	}
	else {
		char *port;
		char *ip_addr;
		
		for (int i = 1; i < argc; ++i) {
			if (strcmp(argv[i], "-h") == 0) {
				help();
			}
			else if (strcmp(argv[i], "-p") == 0) {
				port = argv[++i];
			}
			else if (strcmp(argv[i], "-s") == 0) {
				ip_addr = argv[++i];
			}
		}
    verifyInput(ip_addr, port);
		client(ip_addr, port);
	}
	return 0;
}

