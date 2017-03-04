#include <iostream>
#include <fstream>
#include <vector>
#include <string.h>

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
* Main
*/
int main(int argc, char* argv[]) {
  std::cout << "RSA Tester" << std::endl;

  if (argc != 3) {
    std::cout << "USAGE: ./rsaTester <pub file> <priv file>" << std::endl;
    return 1;
  }

  std::string pubFilename(argv[1]);
  std::string privFilename(argv[2]);
 	
  //std::cout << "Public filename: " << pubFilename << std::endl;
  //std::cout << "Private filename: " << privFilename << std::endl;

  std::vector<char> pubKeyContents = readFileBytes(pubFilename.c_str());
  std::vector<char> privKeyContents = readFileBytes(privFilename.c_str());

  //std::cout << "Public key: " << pubKeyContents.data() << std::endl;
  //std::cout << "Private key: " << privKeyContents.data() << std::endl;

  RSA* pubRSA = getPublicKey(pubKeyContents);
  RSA* privRSA = getPrivateKey(privKeyContents);

  // TEST const char* to vector<char>
  //const char* input = "it was made of stars!\0";
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

  uint32_t msgsize = 1337;
  std::cout << "original int " << msgsize << std::endl;
  std::vector<char> packetVec(sizeof(msgsize));
  memcpy(&packetVec[0], &msgsize, sizeof(msgsize));
  //packetVec.push_back(reinterpret_cast<char>(msgsize));
  
  //std::cout << "Input: " << packetVec.data() << std::endl;
  std::vector<char> encryptedStr = encryptDataWithPublicKey(pubRSA, packetVec);
  //std::cout << "Encrypted Input: " << encryptedStr.data() << std::endl;
  std::vector<char> decryptedStr = decryptDataWithPrivateKey(privRSA, encryptedStr);
  //std::cout << "Decrypted Input: " << decryptedStr.data() << std::endl;
  
  uint32_t newsize;
  memcpy(&newsize, &decryptedStr[0], sizeof(newsize));
  std::cout << "decrypted int " << newsize << std::endl;

	return 0;
}

