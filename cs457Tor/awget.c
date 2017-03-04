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
#include "awget.h"

//
// display help and exit
//
void help() {
  printf("Usage: ./awget <URL> [-c chainfile]\n");
  exit(0);
}

//
// verify ip and port are sound
//
void verifyInput(char *url, char *chainfile) {
  if (!url) {
    printf("ERROR: missing parameters\n");
    help();
  }

  if (access(chainfile,F_OK) == -1) {
    printf("ERROR: chainfile %s cannot be accessed\n", chainfile);
    exit(-1);
  }

  printf("  Request: %s\n", url);
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
  
  uint32_t numSS;
  fscanf(fp, "%d", &numSS);
  meta->numStones = numSS;

  printf("  chainlist is\n");
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

void sendRequestToSteppingStone(ss_t *ss, awget_t *meta)
{

  // Bind to first stepping stone
  int sockfd;
  struct addrinfo hints, *servinfo;
  int rv;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET; //AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = IPPROTO_TCP;//AI_PASSIVE;

  if ((rv = getaddrinfo(ss->ip_addr, ss->port, &hints, &servinfo)) != 0) {
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
  unsigned char *packet = serialize(meta);

  // Send meta data to first stepping stone
  int sendsize = AWGET_SIZE;
  int rc = sendall(sockfd, packet, &sendsize);
  if (rc != 0) {
    printf("ERROR: failed to send html packet\n");
    exit(1);
  }
  
  // Wait to receive the file
  printf("  waiting for file...\n");
  // wait for first packet with webpage size
  unsigned char buffer[sizeof(uint32_t)];
  memset(&buffer[0], 0, sizeof(buffer));
  int recv_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
  if (recv_bytes == 0) {
    printf("Connection closed.\n");
    exit(1);
  } else if (recv_bytes == -1) {
    printf("ERROR: awget recv failed\n");
    fprintf(stderr, "awget: %s\n", gai_strerror(recv_bytes));
    exit(1);
  } else {
    uint32_t net_fsize;
    memcpy(&net_fsize, buffer, sizeof(uint32_t));
    uint32_t fsize = ntohl(net_fsize);

    // receive webpage now
    int rb = 0, b = 0;
    unsigned char *html_packet = (unsigned char*)malloc(fsize+1);
    while (rb < fsize) {
      b = recv(sockfd, (html_packet+rb), fsize, 0);
      rb += b;
      if (b == 0) {
        printf("Connection closed.\n");
        exit(1);
      } else if (b == -1) {
        printf("ERROR: awget2 recv failed\n");
        fprintf(stderr, "awget: %s\n", gai_strerror(b));
        exit(1);
      }
    }
    close(sockfd);

    // write out webpage to disk and exit
    char *start = NULL;
    char *c = meta->url;
    for (int i = 0; i < URL_SIZE; i++) {
      if (*(c++) == '/') {
        start = c;
      }
    }
    if (start == NULL) {
      printf("ERROR: not able to decipher webpage name, did the URL have a file name?\n");
      exit(1);
    }
    char savefile[URL_SIZE];
    strncpy(savefile, start, (c-start));
    
    FILE *pFile;
    pFile = fopen(savefile, "wb");
    fwrite(html_packet , sizeof(unsigned char), fsize, pFile);
    fclose(pFile);
    
    printf("  Received file %s\nGoodbye!\n", savefile);    

    free(html_packet);
  }

  free(packet);
}

// awget flow
// create url,numStones,stones datastructure (wgetData)
// pick a random stepping stone
// connect to stepping stone as client
// serialize wgetData in packet
// send packet to stepping stone
// wait to receive html packet from stepping stone
// deserialize html packet and write it to a file.
int main(int argc, char* argv[])
{
  char *url = NULL;
  char *chainfile = NULL;
  awget_t meta;
  memset(&meta, 0, AWGET_SIZE);
  srand(time(NULL));
  
  if (argc <= 1) {
    help();
  } else {
    chainfile = "./chaingang.txt";

    for (int i = 1; i < argc; ++i) {
      if (strcmp(argv[i], "-h") == 0) {
        help();
      } else if (strcmp(argv[i], "-c") == 0) {
        chainfile = argv[++i];
      } else {
        url = argv[i];
        strncpy(meta.url, url, strlen(url));
      }
    }
    printf("wget:\n");
    verifyInput(url, chainfile);
    readSteppingStoneFile(chainfile, &meta);
    ss_t nextSS = selectRandomSteppingStone(&meta);
    sendRequestToSteppingStone(&nextSS, &meta);
  }
  return 0;
}

