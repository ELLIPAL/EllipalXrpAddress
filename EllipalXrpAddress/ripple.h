#ifndef _RIPPLE_H_
#define _RIPPLE_H_


bool rippleValidateAddress(const std::string& address);
std::string rippleGetAddressFromSecret(const std::string& secretkey);
void rippleGenerateAddress(std::string& address, std::string& secret);

std::string rippleCommandAddressInfo(std::string address);

std::string rippleCommandServerState();

std::string rippleCommandSignedXRPPayment(
	const std::string& addressFrom, const std::string& secretFrom, unsigned int sequence,
	const std::string& addressTo, 
	double xrp, double fee,
	std::string& outTransactionHash);

std::string getAccountSeed(const std::string& secret);
std::string getAccountSecretFromSeed(const std::string& seed);

std::string getAccountprivKeyFromSecret(const std::string& secret);
std::string getAccountPublicKeyFromSecret(const std::string& secret);

#endif
