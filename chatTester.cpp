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

  char buffer[MAXDATASIZE];
  while (1) {
		memset(&buffer[0], 0, sizeof(buffer));
    int recv_bytes = recv(newfd, buffer, sizeof(buffer), 0);
    if (recv_bytes == 0) {
      std::cout << "Chat session closed." << std::endl;
      exit(0);
    } else if (recv_bytes == -1) {
      std::cerr << "ERROR: server recv failed" << std::endl;
      exit(1);
    } else {
			uint16_t recv_version = ntohs(buffer[0] | buffer[1] << 8);
			uint16_t recv_size = ntohs(buffer[2] | buffer[3] << 8);

      std::cout << "Friend: ";
			for (int i = 4; i <= (recv_size+4); i++) {
				//printf("%c", buffer[i]);
				std::cout << buffer[i];
			}
      std::cout << std::endl << "You: ";

      // TODO remove this size limit enforcing
      char msg[140];
			memset(&msg[0], 0, sizeof(msg));
			fgets(msg, 200, stdin);
			while (strlen(msg) > 140) {
        std::cerr << "Error: Input too long.\nYou: ";
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

// ============================================================================
/**
* Main
*/
int main(int argc, char* argv[]) {
  // XXX add ability to take port as input
  std::cout << "Chat Server Tester" << std::endl;

  if (argc == 1) {
    server();
  } else if (argc == 3) {
		char *ip_addr = argv[1];
		char *port = argv[2];
    client(ip_addr, port);
  } else {
    std::cout << "USAGE: ./chatTester [<ip address> <port>]" << std::endl;
    return 1;
  }

  //if (argc != 3) {
  //  std::cout << "USAGE: ./rsaTester <pub file> <priv file>" << std::endl;
  //  return 1;
  //}

  //std::string pubFilename(argv[1]);
  //std::string privFilename(argv[2]);
 	//
  //std::cout << "Public filename: " << pubFilename << std::endl;
  //std::cout << "Private filename: " << privFilename << std::endl;

  //std::vector<char> pubKeyContents = readFileBytes(pubFilename.c_str());
  //std::vector<char> privKeyContents = readFileBytes(privFilename.c_str());

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

