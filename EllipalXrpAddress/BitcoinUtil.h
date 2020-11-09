#ifndef __BITCOIN_UTIL__
#define __BITCOIN_UTIL__

#include "types.h"
#include "uint256.h"


template<typename T1>
inline uint256 SHA256Hash(const T1 pbegin, const T1 pend)
{
	static unsigned char pblank[1];
	uint256 hash1;
	SHA256((pbegin == pend ? pblank : (unsigned char*)&pbegin[0]), (pend - pbegin) * sizeof(pbegin[0]), (unsigned char*)&hash1);
	uint256 hash2;
	SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
	return hash2;
}

inline uint160 Hash160(const std::vector<unsigned char>& vch)
{
	uint256 hash1;
	SHA256(&vch[0], vch.size(), (unsigned char*)&hash1);
	uint160 hash2;
	RIPEMD160((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
	return hash2;
}

#endif
