/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "bip39.h"
#include <openssl/sha.h>
// #include "bip39_chinese_simplified.h"
// #include "bip39_chinese_traditional.h"
#include "bip39_english.h"
#include "memzero.h"
// #include "bip39_french.h"
// #include "bip39_italian.h"
// #include "bip39_japanese.h"
// #include "bip39_spanish.h"


#if USE_BIP39_CACHE

static int bip39_cache_index = 0;

static CONFIDENTIAL struct {
	bool set;
	char mnemonic[256];
	char passphrase[64];
	uint8_t seed[512 / 8];
} bip39_cache[BIP39_CACHE_SIZE];

#endif



int mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy)
{
	if (!mnemonic) {
		return 0;
	}

	uint32_t i = 0, n = 0;

	while (mnemonic[i]) {
		if (mnemonic[i] == ' ') {
			n++;
		}
		i++;
	}
	n++;

	// check number of words
	if (n != 12 && n != 18 && n != 24) {
		return 0;
	}

	char current_word[10];
	uint32_t j, k, ki, bi = 0;
	uint8_t bits[32 + 1];

	memzero(bits, sizeof(bits));
	i = 0;
	while (mnemonic[i]) {
		j = 0;
		while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
			if (j >= sizeof(current_word) - 1) {
				return 0;
			}
			current_word[j] = mnemonic[i];
			i++; j++;
		}
		current_word[j] = 0;
		if (mnemonic[i] != 0) {
			i++;
		}
		k = 0;
		for (;;) {
			if (!wordlist[k]) { // word not found
				return 0;
			}
			if (strcmp(current_word, wordlist[k]) == 0) { // word found on index k
				for (ki = 0; ki < 11; ki++) {
					if (k & (1 << (10 - ki))) {
						bits[bi / 8] |= 1 << (7 - (bi % 8));
					}
					bi++;
				}
				break;
			}
			k++;
		}
	}
	if (bi != n * 11) {
		return 0;
	}
	memcpy(entropy, bits, sizeof(bits));
	return n * 11;
}

int mnemonic_check(const char *mnemonic)
{
	uint8_t bits[32 + 1];
	int seed_len = mnemonic_to_entropy(mnemonic, bits);
	if (seed_len != (12 * 11) && seed_len != (18 * 11) && seed_len != (24 * 11)) {
		return 0;
	}
	int words = seed_len / 11;

	uint8_t checksum = bits[words * 4 / 3];
	SHA256(bits, words * 4 / 3, bits);
	if (words == 12) {
		return (bits[0] & 0xF0) == (checksum & 0xF0); // compare first 4 bits
	} else if (words == 18) {
		return (bits[0] & 0xFC) == (checksum & 0xFC); // compare first 6 bits
	} else if (words == 24) {
		return bits[0] == checksum; // compare 8 bits
	}
	return 0;
}


const char * const *mnemonic_wordlist(void)
{
	return wordlist;
}
