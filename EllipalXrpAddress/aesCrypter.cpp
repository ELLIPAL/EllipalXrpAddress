#include "stdafx.h"
#include "aesCrypter.h"
#include <iomanip>

AEScrypter::AEScrypter() : encrypt_ctx(NULL), decrypt_ctx(NULL) 
{}

AEScrypter::~AEScrypter()
{
	Cleanup();
}

void AEScrypter::Cleanup()
{
	if (encrypt_ctx)
	{
		EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)encrypt_ctx);
		delete encrypt_ctx;
		encrypt_ctx = NULL;
	}

	if (decrypt_ctx)
	{
		EVP_CIPHER_CTX_cleanup((EVP_CIPHER_CTX*)decrypt_ctx);
		delete decrypt_ctx;
		decrypt_ctx = NULL;
	}
}

std::string AEScrypter::GenerateSalt()
{
	unsigned char salt[8];
	if (RAND_bytes(salt,8)!=1)
		return "";
	char result[17];
	sprintf_s(result,17,"%02x%02x%02x%02x%02x%02x%02x%02x", salt[0], salt[1], salt[2], salt[3], salt[4], salt[5], salt[6], salt[7]);

	return result;
}

bool AEScrypter::SetPassword(const std::string& password, const std::string &saltStr, int numRounds)
{
	Cleanup();
	encrypt_ctx = new EVP_CIPHER_CTX;
	decrypt_ctx = new EVP_CIPHER_CTX;


	unsigned char key[32];
	unsigned char iv[32];
	unsigned int saltInt[8];
	unsigned char salt[8];

	if (8 != sscanf(saltStr.c_str(), "%02x%02x%02x%02x%02x%02x%02x%02x", &saltInt[0], &saltInt[1], &saltInt[2], &saltInt[3], &saltInt[4], &saltInt[5], &saltInt[6], &saltInt[7]))
		return false;
	for (int i = 0; i < 8; i++)
		salt[i] = (unsigned char)saltInt[i];

	int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (const unsigned char*)password.c_str(), password.length(), numRounds, key, iv);
	if (i != 32)
		return false;
	EVP_CIPHER_CTX_init((EVP_CIPHER_CTX*)encrypt_ctx);
	EVP_EncryptInit_ex((EVP_CIPHER_CTX*)encrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init((EVP_CIPHER_CTX*)decrypt_ctx);
	EVP_DecryptInit_ex((EVP_CIPHER_CTX*)decrypt_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	return true;
}

bool AEScrypter::encrypt(const std::vector<unsigned char> &plainData, std::vector<unsigned char> &encryptedData)
{
	if (!encrypt_ctx)
		return false;

	EVP_EncryptInit_ex((EVP_CIPHER_CTX*)encrypt_ctx, NULL, NULL, NULL, NULL);

	int cipherLen = plainData.size() + AES_BLOCK_SIZE;
	unsigned char *encryptedTemp = (unsigned char*)malloc(cipherLen);
	EVP_EncryptUpdate((EVP_CIPHER_CTX*)encrypt_ctx, encryptedTemp, &cipherLen, plainData.data(), plainData.size());
		
	int finalLen = 0;
	EVP_EncryptFinal_ex((EVP_CIPHER_CTX*)encrypt_ctx, encryptedTemp + cipherLen, &finalLen);
		
	encryptedData.clear();
	encryptedData.reserve(cipherLen+finalLen);
	for (int i = 0; i < cipherLen+finalLen; i++)
		encryptedData.push_back(encryptedTemp[i]);

	free(encryptedTemp);
	return true;
}

bool AEScrypter::decrypt(const std::vector<unsigned char> &encryptedData, std::vector<unsigned char> &decryptedData)
{	
	if (!decrypt_ctx)
		return false;

	EVP_DecryptInit_ex((EVP_CIPHER_CTX*)decrypt_ctx, NULL, NULL, NULL, NULL);
		
	int encryptedLen = encryptedData.size();
	unsigned char *decryptedTemp = (unsigned char *)malloc(encryptedLen);
	EVP_DecryptUpdate((EVP_CIPHER_CTX*)decrypt_ctx, decryptedTemp, &encryptedLen, encryptedData.data(), encryptedLen);

	int finalLen = 0;
	EVP_DecryptFinal_ex((EVP_CIPHER_CTX*)decrypt_ctx, decryptedTemp + encryptedLen, &finalLen);

	int len = encryptedLen + finalLen;
	decryptedData.reserve(len);
	for (int i = 0; i < len; i++)
		decryptedData.push_back(decryptedTemp[i]);

	free(decryptedTemp);
	return true;
}

/*static*/ std::string AEScrypter::vector2stringHex(const std::vector<unsigned char>& data)
{
	std::string result;
	std::ostringstream oss;
	oss << std::setfill('0');
	for (size_t i = 0; i < data.size(); i++)
	{
		oss << std::setw(2) << std::hex << static_cast<int>(data[i]);
	}
	result.assign(oss.str());
	return result;
}

/*static*/ std::vector<unsigned char> AEScrypter::stringHex2vector(const std::string& data)
{
	std::vector<unsigned char> result;
	size_t sz = data.size() >> 1;
	for (size_t i=0; i<sz; i++)
	{
		std::istringstream iss(data.substr(i*2, 2));
		unsigned int ch;
		iss >> std::hex >> ch;
		result.push_back( static_cast<unsigned char>(ch) );
	}
	return result;
}

std::string AEScrypter::encrypt(const std::string &plainDataHex)
{
	std::vector<unsigned char> plainData = stringHex2vector(plainDataHex);
	std::vector<unsigned char> encryptedData;
	if (!encrypt(plainData, encryptedData))
		return "";
	return vector2stringHex(encryptedData);
}

std::string AEScrypter::decrypt(const std::string &encryptedDataHex)
{
	std::vector<unsigned char> encryptedData = stringHex2vector(encryptedDataHex);
	std::vector<unsigned char> decryptedData;
	if (!decrypt(encryptedData, decryptedData))
		return "";
	return vector2stringHex(decryptedData);
}

std::string AEScrypter::getPasswordHash(const std::string& password)
{	
	unsigned char hash[SHA512_DIGEST_LENGTH];
	memset(hash, 0, sizeof(SHA512_DIGEST_LENGTH));
	SHA512((const unsigned char*)password.c_str(), password.size(), hash);
	std::vector<unsigned char> hashV;
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) 
		hashV.push_back(hash[i]);
	return vector2stringHex(hashV);
}