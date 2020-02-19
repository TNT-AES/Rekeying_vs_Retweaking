#ifndef TYPES_H__
#define TYPES_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <bitset>
#include <math.h>
#include <immintrin.h>
#include <nmmintrin.h>
#include <xmmintrin.h>
#include <emmintrin.h>
#include <pmmintrin.h>
#include <tmmintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>

#ifdef __GNUC__
#include <sched.h>
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long s64;


#if defined(_MSC_VER)
#define ALIGNED_(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define ALIGNED_(x) __attribute__((aligned(x)))
typedef unsigned long long _ULonglong;
#endif
#endif

#if defined(__GNUC__)
template <typename T>
std::string to_string(T value)
{
	std::ostringstream os;
	os << value;
	return os.str();
}
#endif


#define ALIGNED_TYPE_(t,x) t ALIGNED_(x)

#define data_t ALIGNED_TYPE_(u8, 16)

#endif //TYPES_H__