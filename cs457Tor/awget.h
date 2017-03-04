#ifndef awget_h
#define awget_h

#define IP_SIZE 16
#define PORT_SIZE 6
#define URL_SIZE 200
#define MAX_STONES 100
#define AWGET_SIZE 2404
// (16+6)*100 + 200 + 4
typedef struct {
  char ip_addr[IP_SIZE];
  char port[PORT_SIZE];
} ss_t; 

typedef struct {
  uint32_t numStones;
  char url[URL_SIZE];
  ss_t stones[MAX_STONES]; 
} awget_t;

unsigned char* serializeSteppingStones(uint32_t numStones, ss_t stones[])
{
  unsigned char *packet = (unsigned char*)malloc(sizeof(ss_t)*numStones);
  unsigned char *ss = (unsigned char*)malloc(sizeof(ss_t));
  for (uint32_t i = 0; i < numStones; i++) { 
    ss_t stone;
    memcpy(&stone, &stones[i], sizeof(ss_t));
    memcpy(ss, &(stone.ip_addr), IP_SIZE);
    memcpy((ss+IP_SIZE), &(stone.port), PORT_SIZE);
    memcpy((packet + (i * sizeof(ss_t))), ss, sizeof(ss_t));
  }
  
  free(ss);
  return packet;
}

unsigned char* serialize(awget_t *data)
{
  unsigned char *packet = (unsigned char*)malloc(AWGET_SIZE);
  memset(packet, 0, AWGET_SIZE);
  uint32_t net_numStones = htonl(data->numStones);
  memcpy(packet, &net_numStones, sizeof(uint32_t));
  memcpy((packet + sizeof(net_numStones)), &data->url, URL_SIZE);

  unsigned char *stones = serializeSteppingStones(data->numStones, data->stones);
  memcpy((packet + sizeof(net_numStones) + URL_SIZE), stones, (sizeof(ss_t)*data->numStones));
  
  return packet;
}

void deserialize(awget_t *data, unsigned char *packet)
{
  uint32_t net_numStones;
  memcpy(&net_numStones, packet, sizeof(uint32_t));
  data->numStones = ntohl(net_numStones);

  packet += sizeof(uint32_t);
  memcpy(&data->url, packet, URL_SIZE);

  packet += URL_SIZE;
  for (uint32_t i = 0; i < data->numStones; i++) {
    ss_t stone;
    memcpy(stone.ip_addr, packet, IP_SIZE);
    packet += IP_SIZE;
    memcpy(stone.port, packet, PORT_SIZE);
    packet += PORT_SIZE;

    memcpy(&data->stones[i], &stone, sizeof(ss_t));
  }

  return;
}

ss_t selectRandomSteppingStone(awget_t *meta)
{
  ss_t nextSS;
  memset(&nextSS, 0, sizeof(nextSS));
  int r = rand() % meta->numStones;
  // Copy next ss from stones db
  memcpy(&(nextSS.ip_addr), &(meta->stones[r].ip_addr), sizeof(meta->stones[r].ip_addr));
  memcpy(&(nextSS.port), &(meta->stones[r].port), sizeof(meta->stones[r].port));
  printf("  next SS is <%s %s>\n", nextSS.ip_addr, nextSS.port);

  // Munge stones db and update number of available stones
  int src = meta->numStones - 1;
  meta->numStones = src;
  if (src == 0) {
    // No more stones left
    // TODO - need some special handling here potentially
  } else if (r == src) {
    // Stone is last in array so zero it out
    memset(&(meta->stones[r]), 0, sizeof(meta->stones[r].ip_addr));
  } else {
    // Replace the obsolete stone with the last in the array
    memcpy(&(meta->stones[r].port), &(meta->stones[src].port), sizeof(meta->stones[src].port));
    memcpy(&(meta->stones[r].ip_addr), &(meta->stones[src].ip_addr), sizeof(meta->stones[src].ip_addr));
  }

  return nextSS;
}

int sendall(int s, unsigned char *buf, int *len)
{
  int total = 0;        // how many bytes we've sent
  int bytesleft = *len; // how many we have left to send
  int n;

  while(total < *len) {
    n = send(s, buf+total, bytesleft, 0);
    if (n == -1) { break; }
    total += n;
    bytesleft -= n;
  }

  *len = total; // return number actually sent here

  return n==-1?-1:0; // return -1 on failure, 0 on success
}

#endif
