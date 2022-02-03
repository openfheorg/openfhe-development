#ifndef __BASICINT_H__
#define __BASICINT_H__

#if NATIVEINT == 128
#define MAX_MODULUS_SIZE 121
using BasicInteger = unsigned __int128;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 60
using BasicInteger = uint64_t;
typedef unsigned __int128 DoubleNativeInt;
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
#elif NATIVEINT == 64 && !defined(HAVE_INT128)
#define MAX_MODULUS_SIZE 58
using BasicInteger = uint64_t;
typedef uint64_t DoubleNativeInt;
typedef uint64_t uint128_t;
typedef int64_t int128_t;
#elif NATIVEINT == 32
#define MAX_MODULUS_SIZE 28
using BasicInteger = uint32_t;
typedef uint64_t DoubleNativeInt;
#endif

#endif // __BASICINT_H__