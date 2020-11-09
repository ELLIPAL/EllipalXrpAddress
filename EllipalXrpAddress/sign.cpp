#include "stdafx.h"

namespace sign
{

#include "base58.h"
#include "uint256.h"
#include "key.h"
#include "RippleAddress.h"



	void GetAccountKeys(std::string& pubKey, std::string& privKey, const std::string& accSecret);


	void serializeData(std::vector<BYTE> &buffer, const BYTE* data, int len)
	{
		for (int i = len - 1; i >= 0; i--)
			buffer.push_back(data[i]);
	}

//////////////////////////////////////////////////////////////////////////
	
//	Canonical signature

//////////////////////////////////////////////////////////////////////////

	namespace detail {
		struct BigNum
		{
			BIGNUM* num;

			BigNum(const char *hex)
			{
				num = BN_new();
				BN_hex2bn(&num, hex);
			}

			BigNum(){ num = BN_new(); }

			BigNum(unsigned char const* ptr, size_t len)
			{
				num = BN_new();
				BN_bin2bn(ptr, len, num);
			}
			~BigNum() { BN_free(num); }
			operator BIGNUM* () { return num; }
		};

		// The SECp256k1 modulus
		static BigNum modulus("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
	}

	// Returns true if original signature was already canonical
	bool makeCanonicalECDSASig(void* vSig, size_t& sigLen)
	{
		// Signature is (r,s) where 0 < s < g
		// If (g-s)<g, replace signature with (r,g-s)

		unsigned char * sig = reinterpret_cast<unsigned char *> (vSig);
		bool ret = false;

		// Find internals
		int rLen = sig[3];
		int sPos = rLen + 6, sLen = sig[rLen + 5];

		detail::BigNum origS, newS;
		BN_bin2bn(&sig[sPos], sLen, origS);
		BN_sub(newS, detail::modulus, origS);

		if (BN_cmp(origS, newS) == 1)
		{ // original signature is not fully canonical
			unsigned char newSbuf[64];
			int newSlen = BN_bn2bin(newS, newSbuf);

			if ((newSbuf[0] & 0x80) == 0)
			{ // no extra padding byte is needed
				sig[1] = sig[1] - sLen + newSlen;
				sig[sPos - 1] = newSlen;
				memcpy(&sig[sPos], newSbuf, newSlen);
			}
			else
			{ // an extra padding byte is needed
				sig[1] = sig[1] - sLen + newSlen + 1;
				sig[sPos - 1] = newSlen + 1;
				sig[sPos] = 0;
				memcpy(&sig[sPos + 1], newSbuf, newSlen);
			}
			sigLen = sig[1] + 2;
		}
		else
			ret = true;

		return ret;
	}

//////////////////////////////////////////////////////////////////////////

//	Sign serialized transaction

//////////////////////////////////////////////////////////////////////////
	
	//for debugging
#ifdef _DEBUG
	std::string bufferHexstring, signingHashstring1, signaturestring;
#endif

	std::string Bin2Hex(const BYTE* data, int len)
	{
		std::string result;
		for (int i = 0; i < len; i++)
		{
			char hexChar[3];
			sprintf(hexChar, "%02X", data[i]);
			result += hexChar;
		}
		return result;
	}

	std::string signTransaction(std::vector<BYTE> &bufferPreSignature, std::vector<BYTE> &bufferPostSignature, const std::string& privKeyHex, std::string& outTransactionHash)
	{
		std::vector<BYTE> bufferData;
		bufferData = bufferPreSignature;
		bufferData.insert(bufferData.end(), bufferPostSignature.begin(), bufferPostSignature.end());

#ifdef _DEBUG
		bufferHexstring = Bin2Hex(&bufferData[0], bufferData.size());
#endif

		std::vector<BYTE> signingHashData;
		DWORD signPrefix = 0x53545800;
		serializeData(signingHashData, (BYTE*)&signPrefix, 4);
		signingHashData.insert(signingHashData.end(), bufferData.begin(), bufferData.end());
		unsigned char digest[SHA512_DIGEST_LENGTH];
		SHA512(&signingHashData[0], signingHashData.size(), (unsigned char*)&digest);
		int hashLen = SHA512_DIGEST_LENGTH >> 1;

#ifdef _DEBUG
		signingHashstring1 = Bin2Hex(digest, hashLen);
#endif

		EC_KEY* pkey = EC_KEY_new_by_curve_name(NID_secp256k1);
		BIGNUM *privKey = BN_new();
		BN_hex2bn(&privKey, privKeyHex.c_str());
		EC_KEY_set_private_key(pkey, privKey);
		EC_POINT* pubKey = EC_POINT_new(EC_KEY_get0_group(pkey));
		EC_KEY_set_public_key(pkey, pubKey);


		BYTE pchSig[128];
		unsigned int nSize = sizeof(pchSig) / sizeof(pchSig[0]) - 1;

		if (!ECDSA_sign(0, digest, hashLen, pchSig, &nSize, pkey))
		{
			return "";
		}
		size_t signatureLen = nSize;
		makeCanonicalECDSASig(pchSig, signatureLen);

		std::vector<BYTE> signature;
		signature.push_back(0x74);
		signature.push_back(signatureLen);

		for (size_t i = 0; i < signatureLen; i++)
		{
			signature.push_back(pchSig[i]);
		}

#ifdef _DEBUG
		signaturestring = Bin2Hex(pchSig, signatureLen);
#endif

		std::vector<BYTE> bufferResult;
		bufferResult.insert(bufferResult.end(), bufferPreSignature.begin(), bufferPreSignature.end());
		bufferResult.insert(bufferResult.end(), signature.begin(), signature.end());
		bufferResult.insert(bufferResult.end(), bufferPostSignature.begin(), bufferPostSignature.end());


		signingHashData.clear();
		DWORD txnPrefix = 0x54584e00;
		serializeData(signingHashData, (BYTE*)&txnPrefix, 4);
		signingHashData.insert(signingHashData.end(), bufferResult.begin(), bufferResult.end());
		unsigned char digest2[SHA512_DIGEST_LENGTH];
		SHA512(&signingHashData[0], signingHashData.size(), (unsigned char*)&digest2);


		std::string txBlob = Bin2Hex(&bufferResult[0], bufferResult.size());
		outTransactionHash = Bin2Hex(digest2, SHA512_DIGEST_LENGTH);

		return txBlob;
	}


//////////////////////////////////////////////////////////////////////////

//	Serialize transaction

//////////////////////////////////////////////////////////////////////////


	void serializeVariableLengthData(std::vector<BYTE> &buffer, BYTE tag, const std::string& data)
	{
		if (tag)
		{
			buffer.push_back(tag);
			buffer.push_back(data.length() >> 1);
		}
		for (size_t i = 0; i < data.length(); i += 2)
		{
			char ch0 = data[i];
			char ch1 = data[i + 1];
			ch0 -= (ch0 <= '9') ? '0' : 'A' - 10;
			ch1 -= (ch1 <= '9') ? '0' : 'A' - 10;
			buffer.push_back((ch0 << 4) + ch1);
		}
	}

	void serializeAccount(std::vector<BYTE>& buffer, const std::string& account)
	{
		buffer.push_back(0x14);//20: 20bytov = 160bitove cislo konta

		RippleAddress addr;
		addr.SetString(account, VER_ACCOUNT_ID);
		buffer.insert(buffer.end(), addr.GetData().begin(), addr.GetData().end());
	}

	void serializeXRPAmount(std::vector<BYTE>& buffer, ULONGLONG amountDrops)
	{
		amountDrops += (ULONGLONG)(0x4000000000000000);		// = positive number
		serializeData(buffer, (BYTE*)&amountDrops, 8);
	}

	std::string CreateSendXRPTransaction(const std::string& senderAccount, const std::string& senderSecret, const std::string& receiverAccount,
		ULONGLONG amountDrops, ULONGLONG feeDrops, unsigned int sequence, std::string& outTransactionHash)
	{
		//account..
		std::string pubKey, privKey;
		GetAccountKeys(pubKey, privKey, senderSecret);

		//tags
		BYTE transTypeTag = (1 << 4) | 2; //STInt16
		BYTE flagsTag = (2 << 4) | 2; //STInt32
		BYTE sequenceTag = (2 << 4) | 4; //STInt32
		BYTE amountTag = (6 << 4) | 1; //STAmount
		BYTE feeTag = (6 << 4) | 8; //STAmount	
		BYTE signingPubKeyTag = (7 << 4) | 3;//VL
		BYTE accountTag = (8 << 4) | 1; //STAccount
		BYTE destinationTag = (8 << 4) | 3; //STAccount

		//before signature
		std::vector<BYTE> bufferPreSignature;

		int transType = 0; //0 = payment
		bufferPreSignature.push_back(transTypeTag);		//TransactionType
		serializeData(bufferPreSignature, (BYTE*)&transType, 2);

		int nula = 0;
		bufferPreSignature.push_back(flagsTag);			//Flags
		serializeData(bufferPreSignature, (BYTE*)&nula, 4);

		bufferPreSignature.push_back(sequenceTag);		//Sequence
		serializeData(bufferPreSignature, (BYTE*)&sequence, 4);

		bufferPreSignature.push_back(amountTag);		//Amount
		serializeXRPAmount(bufferPreSignature, amountDrops);

		bufferPreSignature.push_back(feeTag);			//Fee
		serializeXRPAmount(bufferPreSignature, feeDrops);

		serializeVariableLengthData(bufferPreSignature, signingPubKeyTag, pubKey); //SigningPubKey

		//after signature
		std::vector<BYTE> bufferPostSignature;

		bufferPostSignature.push_back(accountTag);
		serializeAccount(bufferPostSignature, senderAccount); //Account

		bufferPostSignature.push_back(destinationTag);
		serializeAccount(bufferPostSignature, receiverAccount);//Destination

		std::string tx_blob = signTransaction(bufferPreSignature, bufferPostSignature, privKey, outTransactionHash);

		return tx_blob;
	}
}