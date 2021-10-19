PALISADE supports a number of different math backends

The design goal is to have several math backends available at the same time, and to permit the programmer to choose,
at runtime, which backend to use.

The current implementation supports the availability of several backends, but requires the programmer to make a
compile-time choice of which backend to use as the default type for BigInteger and BigVector in the library.

Math backend selection is controlled by editing src/core/include/math/backend.h. or by adding a CMAKE flag, e.g.

```
 cmake -DMATHBACKEND=4 ..
```

The programmer should select a value for MATHBACKEND; the file contains several options. As indicated in the comments
in this file:

//To select backend, please UNCOMMENT the appropriate line rather than changing the number on the
//uncommented line

By selecting a particular value for MATHBACKEND, the programmer selects a particular default implementation for
BigInteger, BigVector, and for the composite Poly and ciphertext modulus used in DCRTPoly

For native integer arithmetic NativeInteger, NativeVector implementation is available.
The following is the status of the various MATHBACKEND implementations. We expect subsequent releases to remove these
restrictions and expand available options

* MATHBACKEND 2
If the programmer selects MATHBACKEND 2, the maximum size of BigInteger will be set to BigIntegerBitLength, which is defined in
backend.h and which has a default value of 3000 bits. It's advisable to select a value for BigIntegerBitLength that is larger than the double bitwidth of the largest (ciphertext) modulus. This parameter can be decreased for runtime/space optimization when the largest modulus is under 1500 bits.

The underlying implementation is a fixed-size array of native integers. The native integer used in MATHBACKEND 2, which is defined
by the typedef integral_dtype, MUST be uint32_t; using other types is an open work item.

* MATHBACKEND 4
If the programmer selects MATHBACKEND 4, there is no explicit maximum size of BigInteger; the size grows dynamically as needed and
is constrained only by memory.  This implementation requires that UBINT_32 be defined, as is done in the file. Setting UBINT_64 is
currently not functioning and is an open work item.

* MATHBACKEND 6
This is an integration of the NTL library with PALISADE, and is only available when NTL/GMP is enabled using CMAKE.

All implementations for Big/Native Integer/Vector are based on [interface.h](interface.h).

Palisade supports several methods for modular multiplication.
We use the following naming conventions:

* `ModMul(b, mod)` - Naive modular multiplication that uses % operator for modular reduction, and usually slow.

* `ModMul(b, mod, mu)` - Barrett modular multiplication.
`mu` for Barrett modulo can be precomputed by `mod.ComputeMu()`.

* `ModMulFast(b, mod)` - Naive modular multiplication w/ operands < mod

* `ModMulFast(b, mod, mu)` - Barrett modular multiplication w/ operands < mod

* `ModMulFastConst(b, mod, bPrecomp)` - modular multiplication using precomputed information on b, w/ operands < mod.
`bPrecomp` can be precomputed by `b.PrepModMulConst(mod)`. This method is currently implemented only for NativeInteger class. The fastest method.

Naming conventions for standard modular operations:


| Variant | Naive          | Barrett            | Fast Naive         | Fast Barrett           | Fast Const                        |
| ------- | -------------- | ------------------ | ------------------ | ---------------------- | --------------------------------- |
| Mod     | Mod(mod)       | Mod(mod, mu)       | -                  | -                      | -                                 |
| ModAdd  | ModAdd(b, mod) | ModAdd(b, mod, mu) | ModAddFast(b, mod) | -                      | -                                 |
| ModSub  | ModSub(b, mod) | ModSub(b, mod, mu) | ModSubFast(b, mod) | -                      | -                                 |
| ModMul  | ModMul(b, mod) | ModMul(b, mod, mu) | ModMulFast(b, mod) | ModMulFast(b, mod, mu) | ModMulFastConst(b, mod, bPrecomp) |
