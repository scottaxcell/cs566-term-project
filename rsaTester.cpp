#include <iostream>
#include <fstream>
#include <vector>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

std::vector<char> readFileBytes(const std::string& filename)
{
  std::ifstream ifs(filename.c_str(), std::ios::binary|std::ios::ate);
  std::ifstream::pos_type pos = ifs.tellg();

  std::vector<char> result(pos);

  ifs.seekg(0, std::ios::beg);
  ifs.read(&result[0], pos);

  return result;
}

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

int main(int argc, char* argv[]) {
  std::cout << "RSA Tester" << std::endl;

  if (argc != 3) {
    std::cout << "USAGE: ./rsaTester <pub file> <priv file>" << std::endl;
    return 1;
  }

  std::string pubFilename(argv[1]);
  std::string privFilename(argv[2]);
 	
 	//for (int i = 1; i < argc; ++i) {
 	//	if (argv[i] == "-pub") {
 	//		pubFilename = argv[++i];
 	//	}
 	//	else if (argv[i] == "-priv") {
 	//		privFilename = argv[++i];
 	//	}
 	//}
  std::cout << "Public filename: " << pubFilename << std::endl;
  std::cout << "Private filename: " << privFilename << std::endl;

  std::vector<char> pubKeyContents = readFileBytes(pubFilename.c_str());
  std::vector<char> privKeyContents = readFileBytes(privFilename.c_str());

  std::cout << "Public key: " << pubKeyContents.data() << std::endl;
  std::cout << "Private key: " << privKeyContents.data() << std::endl;

  RSA* pubRSA = getPublicKey(pubKeyContents);
  RSA* privRSA = getPrivateKey(privKeyContents);

	return 0;
}

