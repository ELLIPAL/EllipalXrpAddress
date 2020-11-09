#ifndef AESCRYPTER_H
#define AESCRYPTER_H

class AEScrypter
{
public:
	AEScrypter();
	~AEScrypter();
	
	std::string GenerateSalt();
	bool SetPassword(const std::string& password, const std::string& saltStr, int numRounds);

	bool encrypt(const std::vector<unsigned char> &plainData, std::vector<unsigned char> &encryptedData);
	bool decrypt(const std::vector<unsigned char> &encryptedData, std::vector<unsigned char> &decryptedData);

	std::string encrypt(const std::string &plainDataHex);
	std::string decrypt(const std::string &encryptedDataHex);

	std::string getPasswordHash(const std::string& password);

private:
	void Cleanup();
	void* encrypt_ctx;
	void* decrypt_ctx;	

	static std::string vector2stringHex(const std::vector<unsigned char>& data);
	static std::vector<unsigned char> stringHex2vector(const std::string& data);
};

#endif