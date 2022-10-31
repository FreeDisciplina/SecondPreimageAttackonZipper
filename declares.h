#ifndef DECLARES_H__
#define DECLARES_H__

#include <iostream>
#include <fstream>
#include <iomanip>
#include <time.h>
#include <math.h>
#include <string>
#include <immintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h> 
#include <malloc.h>
#include <ipp.h>
#include <ippcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <unordered_map>
#include <list>
#include <set>
#include <unordered_set>
#include <vector>

using namespace std;

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef long double ld64;

#define nMin (16ULL)
#define nMax (32ULL)

#define N (1ULL << n)
#define C ((n >> 1ULL) + (u64)floor(logl(n)/logl(2))) // C ~ n/2 + log(n)

#define et (lp - (u64)ceil(logl(C)/logl(2)))  // C * 2^et = L', 
#define ET (1UL << et) // k, as defined in the paper

#define EL (C * (C - 1) + et * C) // Lower bound on length of expandable messages
#define EU (C * C - 1 + C * (ET + et - 1)) // Upper bound on length of expandable messages

#define ES (C - 1 + et - 1) // Relative index of the last message fragment in the storage

#define t ((n >> 3ULL) * 5ULL) // As defined in the paper
#define T (1ULL << t)

#define r ((n >> 2ULL) + 1ULL) // As defined in the paper
#define R (1ULL << r)

#define w (n >> 1ULL) // As defined in the paper
#define W (1ULL << w)

#define l ((n >> 3ULL) * 3ULL) // As defined in the paper
#define L (1ULL << l)

#define lp ((l > w) ? (l + 1ULL) : (w + 1ULL)) // l'
#define Lp (1ULL << lp) // L'



#define mask ( (N==(1ULL << 32)) ? 0xffffffffUL : ((1ULL << n) - 1ULL))

#define data_t u32

#define BLOCK_SIZE 16
struct mb_t
{
	u8 block[BLOCK_SIZE];
	mb_t()
	{
	};
	mb_t(u8 ablock[BLOCK_SIZE])
	{
		memcpy(block, ablock, sizeof(BLOCK_SIZE));
	};
	mb_t(u64 av)
	{
		((u64 *)block)[0] = av;
		((u64 *)block)[1] = 0ULL;
	};
};

#define INF 0xffffffffffffffffULL

#if defined(__GNUC__)
template <typename T>
std::string to_string(T value)
{
	std::ostringstream os;
	os << value;
	return os.str();
}
#endif

#endif