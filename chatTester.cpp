#include <iostream>
#include <fstream>
#include <vector>

// Chat server includes
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MYPORT "61723"
#define MAXDATASIZE 144 // max bytes we can get at once

// OpenSSL includes
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

// The PADDING parameter means RSA will pad your data for you
//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING
#define PADDING RSA_PKCS1_PADDING
#define KEYSIZE 32
#define IVSIZE 32
#define BLOCKSIZE 256
#define SALTSIZE 8

// ============================================================================
/**
*
*/
int sendall(int s, unsigned char *buf, uint32_t *len)
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

// ============================================================================
/**
*
*/
// ============================================================================
/**
*
*/
std::vector<char> readFileBytes(const std::string& filename)
{
  std::ifstream ifs(filename.c_str(), std::ios::binary|std::ios::ate);
  std::ifstream::pos_type pos = ifs.tellg();

  std::vector<char> result(pos);

  ifs.seekg(0, std::ios::beg);
  ifs.read(&result[0], pos);

  return result;
}

// ============================================================================
/**
*
*/
RSA* getPrivateKey(std::vector<char>& byteArray)
{
  const char* str = byteArray.data();
  BIO* bio = BIO_new_mem_buf((void*)str, -1);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  RSA* rsa = PEM_read_bio_RSAPrivateKey(bio,nullptr, nullptr, nullptr);
  if (!rsa) {
    std::cerr << "Could not load private key" << std::endl;
    return nullptr;
  }

  BIO_free(bio);
  return rsa;
}

// ============================================================================
/**
*
*/
RSA* getPublicKey(std::vector<char>& byteArray)
{
  const char* str = byteArray.data();
  BIO* bio = BIO_new_mem_buf((void*)str, -1);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

  RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio,nullptr, nullptr, nullptr);
  if (!rsa) {
    std::cerr << "Could not load public key" << std::endl;
    return nullptr;
  }

  BIO_free(bio);
  return rsa;
}

// ============================================================================
/**
* Encrpyt data with public RSA
*/
std::vector<char> encryptDataWithPublicKey(RSA* rsa, std::vector<char>& data)
{
    std::vector<char> result;

    int rsaSize = RSA_size(rsa);
    //const unsigned char* from = (const unsigned char*)data.data();

    unsigned char* to = (unsigned char*)malloc(rsaSize);
    //int RSA_public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *rsa, int padding);
    //int resultSize = RSA_public_encrypt(data.size(), (const unsigned char*)from, to, rsa, PADDING);
    int resultSize = RSA_public_encrypt(data.size(), (const unsigned char*)&data[0], to, rsa, PADDING);

    if(resultSize == -1) {
      std::cerr << "Could not encrypt: " << ERR_error_string(ERR_get_error(), nullptr);
      return result;
    }

    ////result = std::vector<char>(reinterpret_cast<char*>(to), resultSize);
    std::string str(reinterpret_cast<char*>(to), resultSize);
    std::cout << "rsaSize: " << rsaSize << std::endl;
    std::cout << "str.size(): " << str.size() << std::endl;
    //result = std::vector<char>(reinterpret_cast<std::vector<char>::size_type>(to), resultSize);
    result = std::vector<char>(str.begin(), str.end());
    //return std::vector<char>(reinterpret_cast<std::vector<char>::size_type>(to), resultSize);
    return result;
}


// ============================================================================
/**
* Decrypt data with private RSA
*/
std::vector<char> decryptDataWithPrivateKey(RSA *key, std::vector<char> &data)
{
    std::vector<char> buffer;
    const unsigned char* encryptedData = (const unsigned char*)data.data();

    int rsaLen = RSA_size(key);

    unsigned char* ed = (unsigned char*)malloc(rsaLen);
    //RSA_public_decrypt() - if you are using the public key
    int resultLen = RSA_private_decrypt(rsaLen, encryptedData, ed, key, PADDING);

    if(resultLen == -1) {
        std::cerr << "Could not decrypt: " << ERR_error_string(ERR_get_error(),NULL);
        return buffer;
    }

    std::string str(reinterpret_cast<const char*>(ed), resultLen);
    std::cout << "rsaSize: " << rsaLen << std::endl;
    std::cout << "str.size(): " << str.size() << std::endl;
    buffer = std::vector<char>(str.begin(), str.end());
    //buffer = std::vector<char>((const char*)ed, resultLen);

    return buffer;
}

// ============================================================================
/**
* Obtain and print the outside ip address of this host
*/
void printPrimaryIp()
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

// ============================================================================
/**
* Server example
*/
void server(RSA *pubRSA, RSA* privRSA) {
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
		std::cerr << "ERROR: getaddrinfo failed" << std::endl;
		exit(1);
	}

	// make a socket, bind it, listen on it
	if ((sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
		std::cerr << "ERROR: socket failed" << std::endl;
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) {
		std::cerr << "ERROR: setsockopt failed" << std::endl;
		exit(1);
	}

	if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
		std::cerr << "ERROR: bind failed" << std::endl;
		exit(1);
	}

	if (listen(sockfd, 10) < 0) {
		std::cerr << "ERROR: listen failed" << std::endl;
		exit(1);
	}
	
	printPrimaryIp();

	// now accept an incoming connection
	addr_size = sizeof(their_addr);
	if ((newfd = accept(sockfd, (struct sockaddr *)&their_addr, &addr_size)) < 0) {
		std::cerr << "ERROR: listen accept" << std::endl;
		exit(1);
	}

	std::cout << "Found a friend! You receive first." << std::endl;

  while (1) {
    uint32_t net_msgsize;
    unsigned char buffer[sizeof(net_msgsize)];
    memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(newfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      printf("Connection closed.\n");
      exit(1);
    } else if (recv_bytes == -1) {
      printf("ERROR: server recv failed\n");
      exit(1);
    } else {
      // read received msgsize
      memcpy(&net_msgsize, buffer, sizeof(net_msgsize));
      uint32_t msgsize = ntohl(net_msgsize);
      std::cout << "DEBUG: server incoming packet is " << msgsize << " bytes." << std::endl;

      // receive rest of the packet
      int totalReceived = 0, received = 0;
      unsigned char *recv_packet = (unsigned char*)malloc(msgsize+1);
      while (totalReceived < msgsize) {
        received = recv(newfd, (recv_packet+totalReceived), msgsize, 0);
        totalReceived += received;
        if (received == 0) {
          printf("Connection closed.\n");
          exit(1);
        } else if (received == -1) {
          printf("ERROR: server recv failed\n");
          fprintf(stderr, "server: %s\n", gai_strerror(received));
          exit(1);
        }
      }
      std::cout << "DEBUG: server received " << totalReceived << " bytes." << std::endl;

      std::cout << "Friend: ";
			for (int i = 0; i <= msgsize; i++) {
				printf("%c", recv_packet[i]);
			}
      free(recv_packet);

      std::cout << std::endl << "You: ";
      
      std::string userInput;
      std::getline(std::cin, userInput); // stops reading at newline

	    msgsize = userInput.size();
	    net_msgsize = htonl(msgsize);
      
      std::cout << "DEBUG server input size " << msgsize << std::endl;
      std::cout << "DEBUG server input '" << userInput << "'" << std::endl;

      // packet format: msgsize, msg
      uint32_t packetsize = (sizeof(net_msgsize) + msgsize);
	    char packet[packetsize];
	    memset(&packet[0], 0, sizeof(packet)); // zero out packet contents
      memcpy(&packet[0], &net_msgsize, sizeof(net_msgsize)); // copy net message size into buffer
      strncpy(&packet[sizeof(msgsize)], userInput.c_str(), msgsize); // copy message into buffer

      std::cout << "DEBUG: server wants to send " << packetsize << " bytes." << std::endl;
      std::cout << "DEBUG: server packet to send: ";
	    for (int i = sizeof(net_msgsize); i < packetsize; i++) {
	    	printf("%c", packet[i]);
	    }
      std::cout << std::endl;


      int32_t rc = sendall(newfd, (unsigned char*)packet, &packetsize);
      if (rc != 0) {
        std::cerr << "ERROR: failed to send data" << std::endl;
        exit(1);
      }
      std::cout << "DEBUG: server sent " << packetsize << " bytes." << std::endl;

    }
  }
}

// ============================================================================
/**
* Get sockaddr, IPv4 or IPv6
*/
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// ============================================================================
/**
* Client example
*/
void client(char *ip_addr, char *port, RSA *pubRSA, RSA *privRSA) {
	std:: cout << "Connecting to server... " << std::endl;

	int sockfd;
	struct addrinfo hints, *servinfo;
	int rv;
	char server_ip[INET_ADDRSTRLEN];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET; //AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(ip_addr, port, &hints, &servinfo)) != 0) {
		std::cerr << "ERROR: getaddrinfo failed" << std::endl;
		exit(1);
	}

	if ((sockfd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) < 0) {
		std::cerr << "ERROR: client socket failed" << std::endl;
		exit(1);
	}

	if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) < 0) {
		std::cerr << "ERROR: client connect failed" << std::endl;
		exit(1);
	}

	inet_ntop(servinfo->ai_family, get_in_addr((struct sockaddr *)servinfo->ai_addr), server_ip, sizeof(server_ip));
	std::cout << "Connected!" << std::endl;
	std::cout << "Connected to a friend! You send first." << std::endl;

  std::cout << "You: ";
  std::string userInput;
  std::getline(std::cin, userInput); // stops reading at newline

	uint32_t msgsize = userInput.size();
	uint32_t net_msgsize = htonl(msgsize);
  
  std::cout << "DEBUG client input size " << msgsize << std::endl;
  std::cout << "DEBUG client input '" << userInput << "'" << std::endl;

  // Encrypt user input
  //std::copy(userInput.begin(), userInput.end(), std::back_inserter(packetVec));
  //std::vector<char> inputData(userInput.begin(), userInput.end());
  //std::vector<char> encryptedStr = encryptDataWithPublicKey(pubRSA, inputData);
  //std::cout << "Encrypted Input: " << encryptedStr.data() << std::endl;
  //std::vector<char> decryptedStr = decryptDataWithPrivateKey(privRSA, encryptedStr);
  //std::cout << "Decrypted Input: " << decryptedStr.data() << std::endl;

  // packet format: msgsize, msg
  uint32_t packetsize = (sizeof(net_msgsize) + msgsize);
	char packet[packetsize];
	memset(&packet[0], 0, sizeof(packet)); // zero out packet contents
  memcpy(&packet[0], &net_msgsize, sizeof(net_msgsize)); // copy net message size into buffer
  strncpy(&packet[sizeof(msgsize)], userInput.c_str(), msgsize); // copy message into buffer

  std::cout << "DEBUG: client wants to send " << packetsize << " bytes." << std::endl;
  std::cout << "DEBUG: client packet to send: ";
	for (int i = sizeof(net_msgsize); i < packetsize; i++) {
		printf("%c", packet[i]);
	}
  std::cout << std::endl;

  int32_t rc = sendall(sockfd, (unsigned char*)packet, &packetsize);
  if (rc != 0) {
    std::cerr << "ERROR: failed to send data" << std::endl;
    exit(1);
  }
  std::cout << "DEBUG: client sent " << packetsize << " bytes." << std::endl;

  while (1) {
    unsigned char buffer[sizeof(net_msgsize)];
    memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      printf("Connection closed.\n");
      exit(1);
    } else if (recv_bytes == -1) {
      printf("ERROR: client recv failed\n");
      exit(1);
    } else {
      // read received msgsize
      memcpy(&net_msgsize, buffer, sizeof(net_msgsize));
      msgsize = ntohl(net_msgsize);
      std::cout << "DEBUG: client incoming packet is " << msgsize << " bytes." << std::endl;

      // receive rest of the packet
      int totalReceived = 0, received = 0;
      unsigned char *recv_packet = (unsigned char*)malloc(msgsize+1);
      while (totalReceived < msgsize) {
        received = recv(sockfd, (recv_packet+totalReceived), msgsize, 0);
        totalReceived += received;
        if (received == 0) {
          printf("Connection closed.\n");
          exit(1);
        } else if (received == -1) {
          printf("ERROR: client recv failed\n");
          fprintf(stderr, "client: %s\n", gai_strerror(received));
          exit(1);
        }
      }
      std::cout << "DEBUG: client received " << totalReceived << " bytes." << std::endl;

      std::cout << "Friend: ";
			for (int i = 0; i <= msgsize; i++) {
				printf("%c", recv_packet[i]);
			}
      free(recv_packet);

      std::cout << std::endl << "You: ";
      
      std::string userInput;
      std::getline(std::cin, userInput); // stops reading at newline

	    uint32_t msgsize = userInput.size();
	    uint32_t net_msgsize = htonl(msgsize);
      
      std::cout << "DEBUG client input size " << msgsize << std::endl;
      std::cout << "DEBUG client input '" << userInput << "'" << std::endl;

      // packet format: msgsize, msg
      uint32_t packetsize = (sizeof(net_msgsize) + msgsize);
	    char packet[packetsize];
	    memset(&packet[0], 0, sizeof(packet)); // zero out packet contents
      memcpy(&packet[0], &net_msgsize, sizeof(net_msgsize)); // copy net message size into buffer
      strncpy(&packet[sizeof(msgsize)], userInput.c_str(), msgsize); // copy message into buffer

      std::cout << "DEBUG: client wants to send " << packetsize << " bytes." << std::endl;
      std::cout << "DEBUG: client packet to send: ";
	    for (int i = sizeof(net_msgsize); i < packetsize; i++) {
	    	printf("%c", packet[i]);
	    }
      std::cout << std::endl;


      int32_t rc = sendall(sockfd, (unsigned char*)packet, &packetsize);
      if (rc != 0) {
        std::cerr << "ERROR: failed to send data" << std::endl;
        exit(1);
      }
      std::cout << "DEBUG: client sent " << packetsize << " bytes." << std::endl;

    }
  }
}

// ============================================================================
/**
* Main
*/
int main(int argc, char* argv[]) {
  // XXX
  // - DONE add ability to send/receive variable data sizes
  // - add network serialization/deserialization on data
  // - add ability to take public RSA file as input
  // - add abilitiy to take private RSA file as input
  // - add encryption of data using public RSA
  // - add decryption of data using private RSA
  // - add ability to take port as input
  
  std::cout << "Chat Server Tester" << std::endl;

  if (argc == 3) {
    std::string pubFilename(argv[1]);
    std::string privFilename(argv[2]);
    std::vector<char> pubKeyContents = readFileBytes(pubFilename.c_str());
    std::vector<char> privKeyContents = readFileBytes(privFilename.c_str());
    RSA* pubRSA = getPublicKey(pubKeyContents);
    RSA* privRSA = getPrivateKey(privKeyContents);


    server(pubRSA, privRSA);
  } else if (argc == 5) {
    std::string pubFilename(argv[1]);
    std::string privFilename(argv[2]);
    std::vector<char> pubKeyContents = readFileBytes(pubFilename.c_str());
    std::vector<char> privKeyContents = readFileBytes(privFilename.c_str());
    RSA* pubRSA = getPublicKey(pubKeyContents);
    RSA* privRSA = getPrivateKey(privKeyContents);
		char *ip_addr = argv[3];
		char *port = argv[4];

    client(ip_addr, port, pubRSA, privRSA);
  } else {
    std::cout << "USAGE: ./chatTester <pub file> <priv file> [<ip address> <port>]" << std::endl;
    return 1;
  }

  //if (argc != 3) {
  //  std::cout << "USAGE: ./rsaTester <pub file> <priv file>" << std::endl;
  //  return 1;
  //}


  //std::cout << "Public key: " << pubKeyContents.data() << std::endl;
  //std::cout << "Private key: " << privKeyContents.data() << std::endl;

  //RSA* pubRSA = getPublicKey(pubKeyContents);
  //RSA* privRSA = getPrivateKey(privKeyContents);

  //// TEST const char* to vector<char>
  ////const char* input = "it was made of stars!\0";
  //const char* input = "if i were YOU, then I would n0t be me... 123456789 -- #sorrynotsorry\0";
  //std::string inputStr(input);
  ////std::vector<char> inputVec(reinterpret_cast<std::vector<char>::size_type>(inputStr.c_str()), inputStr.size());
  //std::vector<char> inputVec(inputStr.begin(), inputStr.end());
  ////std::vector<char>::size_type inputSize = strlen((const char*)input);
  ////std::vector<char> inputVec(input, input + inputSize);
  //std::cout << "Input: " << inputVec.data() << std::endl;
  //std::vector<char> encryptedStr = encryptDataWithPublicKey(pubRSA, inputVec);
  //std::cout << "Encrypted Input: " << encryptedStr.data() << std::endl;
  //std::vector<char> decryptedStr = decryptDataWithPrivateKey(privRSA, encryptedStr);
  //std::cout << "Decrypted Input: " << decryptedStr.data() << std::endl;
  //if (inputVec == decryptedStr) {
  //  std::cout << "ENCRYPTION/DECRYPTION SUCCESSFUL" << std::endl;
  //} else {
  //  std::cout << "ENCRYPTION/DECRYPTION FAILED" << std::endl;
  //}

	return 0;
}

