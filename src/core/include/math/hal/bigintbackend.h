#ifndef __BIGINTBACKEND_H__
#define __BIGINTBACKEND_H__

/*! Define the underlying default math implementation being used by defining
 * MATHBACKEND */

// Each math backend is defined in its own namespace, and can be used at any
// time by referencing the objects in its namespace

// Selecting a math backend by defining MATHBACKEND means defining which
// underlying implementation is the default BigInteger and BigVector

// note that we #define how many bits the underlying integer can store as a
// guide for users of the backends

// MATHBACKEND 2
//    Uses bigintfxd:: definition as default
//    Implemented as a vector of integers
//    Configurable maximum bit length and type of underlying integer

// MATHBACKEND 4
//     This uses bigintdyn:: definition as default
//     This backend supports arbitrary bitwidths; no memory pool is
// used; can grow up to RAM limitation
//    Configurable type of underlying integer (either 32 or 64 bit)

// passes all tests with UBINTDYN_32
// fails tests with UBINTDYN_64
// there is a bug in the way modulus is computed. do not use.

// MATHBACKEND 6
//     This uses bigintntl:: definition as default
//     GMP 6.1.2 / NTL 10.3.0 backend

// To select backend, please UNCOMMENT the appropriate line rather than changing
// the number on the uncommented line (and breaking the documentation of the
// line)

#include "math/hal/bigintfxd/backendfxd.h"
#include "math/hal/bigintdyn/backenddyn.h"
#include "math/hal/bigintntl/backendntl.h"

#ifndef MATHBACKEND
#define MATHBACKEND 2
// #define MATHBACKEND 4
// #define MATHBACKEND 6
#endif

#if MATHBACKEND != 2 && MATHBACKEND != 4 && MATHBACKEND != 6
#error "MATHBACKEND value is not valid"
#endif

/**
 * @namespace bigintbackend
 * The namespace of bigintbackend
 */
namespace bigintbackend {

#if MATHBACKEND == 2

using BigInteger = M2Integer;
using BigVector = M2Vector;

#elif MATHBACKEND == 4

#ifdef UBINT_64
#error MATHBACKEND 4 with UBINT_64 currently does not work do not use.
#endif

using BigInteger = M4Integer;
using BigVector = M4Vector;

#elif MATHBACKEND == 6

using BigInteger = M6Integer;
using BigVector = M6Vector;

#endif

}  // namespace bigintbackend

#endif // __BIGINTBACKEND_H__