// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


//
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all alphanumeric.
//
#ifndef BITCOIN_BASE58_H
#define BITCOIN_BASE58_H


#include "bignum.h"

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


static const char* ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

inline std::string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend)
{
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;

    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    std::vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    std::reverse_copy(pbegin, pend, vchTmp.begin());

    // Convert little endian data to bignum
    CBigNum bn(vchTmp);

    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
            throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getuint();
        str += ALPHABET[c];
    }

    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
        str += ALPHABET[0];

    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

inline std::string EncodeBase58(const std::vector<unsigned char>& vch)
{
    return EncodeBase58(&vch[0], &vch[0] + vch.size());
}

inline bool DecodeBase58(const char* psz, std::vector<unsigned char>& vchRet)
{
    CAutoBN_CTX pctx;
    vchRet.clear();
    CBigNum bn58 = 58;
    CBigNum bn = 0;
    CBigNum bnChar;
    while (isspace(*psz))
        psz++;

    // Convert big endian string to bignum
    for (const char* p = psz; *p; p++)
    {
        const char* p1 = strchr(ALPHABET, *p);
        if (p1 == NULL)
        {
            while (isspace(*p))
                p++;
            if (*p != '\0')
                return false;
            break;
        }
        bnChar.setuint(p1 - ALPHABET);
        if (!BN_mul(&bn, &bn, &bn58, pctx))
            throw bignum_error("DecodeBase58 : BN_mul failed");
        bn += bnChar;
    }

    // Get bignum as little endian data
    std::vector<unsigned char> vchTmp = bn.getvch();

    // Trim off sign byte if present
    if (vchTmp.size() >= 2 && vchTmp.end()[-1] == 0 && vchTmp.end()[-2] >= 0x80)
        vchTmp.erase(vchTmp.end()-1);

    // Restore leading zeros
    int nLeadingZeros = 0;
    for (const char* p = psz; *p == ALPHABET[0]; p++)
        nLeadingZeros++;
    vchRet.assign(nLeadingZeros + vchTmp.size(), 0);

    // Convert little endian data to big endian
    std::reverse_copy(vchTmp.begin(), vchTmp.end(), vchRet.end() - vchTmp.size());
    return true;
}

inline bool DecodeBase58(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58(str.c_str(), vchRet);
}





inline std::string EncodeBase58Check(const std::vector<unsigned char>& vchIn)
{
    // add 4-byte hash check to the end
    std::vector<unsigned char> vch(vchIn);
    uint256 hash = SHA256Hash(vch.begin(), vch.end());
    vch.insert(vch.end(), (unsigned char*)&hash, (unsigned char*)&hash + 4);
    return EncodeBase58(vch);
}

inline bool DecodeBase58Check(const char* psz, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(psz, vchRet))
        return false;
    if (vchRet.size() < 4)
    {
        vchRet.clear();
        return false;
    }
    uint256 hash = SHA256Hash(vchRet.begin(), vchRet.end()-4);
    if (memcmp(&hash, &vchRet.end()[-4], 4) != 0)
    {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size()-4);
    return true;
}

inline bool DecodeBase58Check(const std::string& str, std::vector<unsigned char>& vchRet)
{
    return DecodeBase58Check(str.c_str(), vchRet);
}


class CBase58Data
{
public:
    unsigned char nVersion;
    std::vector<unsigned char> vchData;

    CBase58Data() : nVersion(1)
    { ; }

    ~CBase58Data()
    {
        if (!vchData.empty())
            memset(&vchData[0], 0, vchData.size());
    }

	const std::vector<unsigned char>& GetData()
	{
		return vchData;
	}

	//template <size_t Bits, class Tag>
	//void SetData (int version, base_uint<Bits, Tag> const& from)
	void SetData (int version, uint256 const& from)
	{
		nVersion = version;

		vchData.clear();
		vchData.reserve (from.size ());

		for (const unsigned char* p = from.begin(); p<from.end();p++)
			vchData.push_back(*p);
		

		//std::copy(std::begin (from), std::end(from), std::begin (vchData));
	}

    void SetData(int nVersionIn, const std::vector<unsigned char>& vchDataIn)
    {
		nVersion    = nVersionIn;
		vchData	    = vchDataIn;
    }

    void SetData(int nVersionIn, const void* pdata, size_t nSize)
    {
        nVersion = nVersionIn;
        vchData.resize(nSize);
        if (nSize)
            memcpy(&vchData[0], pdata, nSize);
    }

    void SetData(int nVersionIn, const unsigned char *pbegin, const unsigned char *pend)
    {
        SetData(nVersionIn, (void*)pbegin, pend - pbegin);
    }

    bool SetString(const char* psz, unsigned char version)
    {
        std::vector<unsigned char> vchTemp;
        DecodeBase58Check(psz, vchTemp);
        if (vchTemp.empty() || vchTemp[0] != version)
        {
            vchData.clear();
            nVersion = 1;
            return false;
        }
        nVersion = vchTemp[0];
        vchData.resize(vchTemp.size() - 1);
        if (!vchData.empty())
            memcpy(&vchData[0], &vchTemp[1], vchData.size());
        memset(&vchTemp[0], 0, vchTemp.size());
        return true;
    }

    bool SetString(const std::string& str, unsigned char version)
    {
        return SetString(str.c_str(), version);
    }

    std::string ToString() const
    {
        std::vector<unsigned char> vch(1, nVersion);

		vch.insert(vch.end(), vchData.begin(), vchData.end());

        return EncodeBase58Check(vch);
    }

    int CompareTo(const CBase58Data& b58) const
    {
        if (nVersion < b58.nVersion) return -1;
        if (nVersion > b58.nVersion) return  1;
        if (vchData < b58.vchData)   return -1;
        if (vchData > b58.vchData)   return  1;
        return 0;
    }

    bool operator==(const CBase58Data& b58) const { return CompareTo(b58) == 0; }
    bool operator!=(const CBase58Data& b58) const { return CompareTo(b58) != 0; }
    bool operator<=(const CBase58Data& b58) const { return CompareTo(b58) <= 0; }
    bool operator>=(const CBase58Data& b58) const { return CompareTo(b58) >= 0; }
    bool operator< (const CBase58Data& b58) const { return CompareTo(b58) <  0; }
    bool operator> (const CBase58Data& b58) const { return CompareTo(b58) >  0; }

	friend std::size_t hash_value(const CBase58Data& b58);
};

extern std::size_t hash_value(const CBase58Data& b58);

#endif
// vim:ts=4
