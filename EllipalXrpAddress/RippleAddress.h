#ifndef _RIPPLE_ADDRESS_H_
#define _RIPPLE_ADDRESS_H_

typedef enum {
    VER_NONE                = 1,
    VER_NODE_PUBLIC         = 28,
    VER_NODE_PRIVATE        = 32,
    VER_ACCOUNT_ID          = 0,
    VER_ACCOUNT_PUBLIC      = 35,
    VER_ACCOUNT_PRIVATE     = 34,
    VER_FAMILY_GENERATOR    = 41,
    VER_FAMILY_SEED         = 33,
} VersionEncoding;

class RippleAddress : public CBase58Data
{
public:
    void setSeed(uint128 hash);
    uint128 getSeed() const;
    const std::vector<unsigned char>& getAccountPublic() const;
	void setAccountPublic(const std::vector<unsigned char>& generator, int seq);
    uint160 getAccountID() const;
    void setAccountID(const uint160& hash160);
    std::string humanAccountID() const;
    std::string humanSeed() const;
        std::vector<unsigned char> const& getGenerator () const;

	void setAccountPrivate (RippleAddress const& generator, RippleAddress const& naSeed, int seq);
	void setAccountPrivate (uint256 hash256);
};

void RippleAddress::setSeed(uint128 hash)
{
    SetData(VER_FAMILY_SEED, hash.begin(), 16);
}

uint128 RippleAddress::getSeed() const
{
    return uint128(vchData);
}

const std::vector<unsigned char>& RippleAddress::getAccountPublic() const
{
    return vchData;
}

void RippleAddress::setAccountPublic(const std::vector<unsigned char>& generator, int seq)
{
    CKey    pubkey(generator, seq);
    SetData(VER_ACCOUNT_PUBLIC, pubkey.GetPubKey());
}

void RippleAddress::setAccountPrivate (RippleAddress const& generator, RippleAddress const& naSeed, int seq)
{
	CKey    ckPubkey    = CKey (naSeed.getSeed ());
	CKey    ckPrivkey   = CKey (generator, ckPubkey.GetSecretBN (), seq);
	uint256 uPrivKey;

	ckPrivkey.GetPrivateKeyU (uPrivKey);

	setAccountPrivate (uPrivKey);
}

void RippleAddress::setAccountPrivate (uint256 hash256)
{
	SetData(VER_ACCOUNT_PRIVATE, hash256);
}

uint160 RippleAddress::getAccountID() const
{
    switch (nVersion) {
    case VER_NONE:
        throw std::runtime_error("unset source - getAccountID");

    case VER_ACCOUNT_ID:
        return uint160(vchData);

    case VER_ACCOUNT_PUBLIC:
        // Note, we are encoding the left.
        return Hash160(vchData);

    default:
        throw std::runtime_error("bad source");
    }
}

void RippleAddress::setAccountID(const uint160& hash160)
{
    SetData(VER_ACCOUNT_ID, hash160.begin(), 20);
}

std::string RippleAddress::humanAccountID() const
{
    switch (nVersion) {
    case VER_NONE:
        throw std::runtime_error("unset source - humanAccountID");

    case VER_ACCOUNT_ID:
    {
        return ToString();
    }
    
    case VER_ACCOUNT_PUBLIC:
    {
        RippleAddress   accountID;

        (void) accountID.setAccountID(getAccountID());

        return accountID.ToString();
    }

    default:
        throw std::runtime_error("bad source");
    }
}

std::string RippleAddress::humanSeed() const
{
    switch (nVersion) {
    case VER_NONE:
        throw std::runtime_error("unset source - humanSeed");

    case VER_FAMILY_SEED:
        return ToString();

    default:
        throw std::runtime_error("bad source");
    }
}

std::vector<unsigned char> const& RippleAddress::getGenerator () const
{
	// returns the public generator
	switch (nVersion)
	{
	case VER_NONE:
		throw std::runtime_error ("unset source - getGenerator");

	case VER_FAMILY_GENERATOR:
		// Do nothing.
		return vchData;

	default:
		throw std::runtime_error ("bad source");
	}
}

EC_KEY* GeneratePrivateDeterministicKey(RippleAddress const& pubGen, const BIGNUM* rootPrivKey, int seq)
{
	// privateKey(n) = (rootPrivateKey + Hash(pubHash|seq)) % order
	BN_CTX* ctx = BN_CTX_new();

	if (ctx == nullptr) return nullptr;

	EC_KEY* pkey = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (pkey == nullptr)
	{
		BN_CTX_free(ctx);
		return nullptr;
	}

	EC_KEY_set_conv_form(pkey, POINT_CONVERSION_COMPRESSED);

	BIGNUM* order = BN_new();

	if (order == nullptr)
	{
		BN_CTX_free(ctx);
		EC_KEY_free(pkey);
		return nullptr;
	}

	if (!EC_GROUP_get_order(EC_KEY_get0_group(pkey), order, ctx))
	{
		BN_free(order);
		BN_CTX_free(ctx);
		EC_KEY_free(pkey);
		return nullptr;
	}

	// calculate the private additional key
	BIGNUM* privKey = makeHash(pubGen.getGenerator(), seq, order);

	if (privKey == nullptr)
	{
		BN_free(order);
		BN_CTX_free(ctx);
		EC_KEY_free(pkey);
		return nullptr;
	}

	// calculate the final private key
	BN_mod_add(privKey, privKey, rootPrivKey, order, ctx);
	BN_free(order);
	EC_KEY_set_private_key(pkey, privKey);

	// compute the corresponding public key
	EC_POINT* pubKey = EC_POINT_new(EC_KEY_get0_group(pkey));

	if (!pubKey)
	{
		BN_clear_free(privKey);
		BN_CTX_free(ctx);
		EC_KEY_free(pkey);
		return nullptr;
	}

	if (EC_POINT_mul(EC_KEY_get0_group(pkey), pubKey, privKey, nullptr, nullptr, ctx) == 0)
	{
		BN_clear_free(privKey);
		EC_POINT_free(pubKey);
		EC_KEY_free(pkey);
		BN_CTX_free(ctx);
		return nullptr;
	}

	BN_clear_free(privKey);
	EC_KEY_set_public_key(pkey, pubKey);

	EC_POINT_free(pubKey);
	BN_CTX_free(ctx);

	return pkey;
}


RippleAddress createGeneratorPublic(const RippleAddress& naSeed)
{
	CKey            ckSeed(naSeed.getSeed());
	RippleAddress   naNew;
	naNew.SetData(VER_FAMILY_GENERATOR, ckSeed.GetPubKey());
	return naNew;
}

RippleAddress createAccountPrivate(RippleAddress const& generator, RippleAddress const& naSeed, int iSeq)
{
	RippleAddress   naNew;
	naNew.setAccountPrivate(generator, naSeed, iSeq);
	return naNew;
}

void GetAccountKeys(std::string& pubKey, std::string& privKey, const std::string& accSecret)
{
	RippleAddress secret;
	secret.SetString(accSecret, VER_FAMILY_SEED);

	RippleAddress masterGenerator = createGeneratorPublic(secret);
	RippleAddress masterAccountPublic;
	masterAccountPublic.setAccountPublic(masterGenerator.getAccountPublic(), 0);
    std::vector<unsigned char> pubHex = masterAccountPublic.GetData();
	pubKey = strHex(pubHex.begin(), pubHex.size());

    RippleAddress naAccountPrivate = createAccountPrivate(masterGenerator, secret, 0);
    std::vector<unsigned char> privHex = naAccountPrivate.GetData();
	privKey = strHex(privHex.begin(), privHex.size());
}

#endif
