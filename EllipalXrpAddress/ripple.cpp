#include "stdafx.h"

#include "base58.h"
#include "uint256.h"
#include "key.h"
#include "RippleAddress.h"


namespace sign {
	std::string CreateSendXRPTransaction(const std::string& senderAccount, const std::string& senderSecret, const std::string& receiverAccount, ULONGLONG amountDrops, ULONGLONG feeDrops, unsigned int sequence, std::string& outTransactionHash);
}



void getRand(unsigned char *buf, int num)
{
	if (RAND_bytes(buf, num) != 1)
	{
		assert(false);
		throw std::runtime_error("Entropy pool not seeded");
	}
}

bool rippleValidateAddress(const std::string& address)
{
	RippleAddress addr;
	return addr.SetString(address, VER_ACCOUNT_ID);
}

std::string rippleGetAddressFromSecret(const std::string& secretkey)
{
	RippleAddress secret;
	if (!secret.SetString(secretkey, VER_FAMILY_SEED))
		return "";

	RippleAddress masterGenerator = createGeneratorPublic(secret);
	RippleAddress masterAccountPublic;
	masterAccountPublic.setAccountPublic(masterGenerator.getAccountPublic(), 0);
	return masterAccountPublic.humanAccountID();
}


void rippleGenerateAddress(std::string& address, std::string& secret)
{
	RippleAddress naSeed;
	RippleAddress naAccount;

	uint128 key;
	getRand(key.begin(), key.size());

	naSeed.setSeed(key);
	RippleAddress naGenerator = createGeneratorPublic(naSeed);
	naAccount.setAccountPublic(naGenerator.getAccountPublic(), 0);

	secret = naSeed.humanSeed();
	address = naAccount.humanAccountID();
}

std::string rippleCommandAddressInfo(std::string address)
{
    std::stringstream strm;
	strm << "{\"command\": \"account_info\",\"account\": \"" << address << "\",\"ledger\": \"closed\"}";
	return strm.str();
}

std::string rippleCommandServerState()
{
    return "{\"command\":\"server_state\"}";
}

std::string rippleCommandSignedXRPPayment(
	const std::string& addressFrom, const std::string& secretFrom, unsigned int sequence,
	const std::string& addressTo,
	double xrp, double fee,
	std::string& outTransactionHash)
{

	std::string tx_blob = sign::CreateSendXRPTransaction(addressFrom, secretFrom, addressTo, ULONGLONG(xrp*ULONGLONG(1000000)), ULONGLONG(fee*ULONGLONG(1000000)), sequence, outTransactionHash);

	std::string result = "{\"command\": \"submit\", \"tx_blob\": \"" + tx_blob + "\"}";
	return result;	
}

std::string getAccountSeed(const std::string& secret)
{
	RippleAddress addr;
	addr.SetString(secret, VER_FAMILY_SEED);
	uint128 seed = addr.getSeed();
	return seed.GetHex();
}

std::string getAccountSecretFromSeed(const std::string& seed)
{
	RippleAddress addr;
	uint128 seed128;
	seed128.SetHex(seed);



	addr.setSeed(seed128);
	return addr.humanSeed();
}

std::string getAccountprivKeyFromSecret(const std::string& secret)
{
	std::string pubKey, privKey;
	GetAccountKeys(pubKey, privKey, secret);

	return privKey;
}

std::string getAccountPublicKeyFromSecret(const std::string& secret)
{
	std::string pubKey, privKey;
	GetAccountKeys(pubKey, privKey, secret);

	return pubKey;
}