#ifndef __UTILS__
#define __UTILS__

#include "types.h"
#include "ByteOrder.h"

static char charHex(int iDigit)
{
	return iDigit < 10 ? '0' + iDigit : 'A' - 10 + iDigit;
}

template<class Iterator>
std::string strHex(Iterator first, int iSize)
{
	std::string		strDst;
	strDst.resize(iSize*2);
	for (int i = 0; i < iSize; i++) {
		unsigned char c	= *first++;

		strDst[i*2]		= charHex(c >> 4);
		strDst[i*2+1]	= charHex(c & 15);
	}
	return strDst;
}

#endif
