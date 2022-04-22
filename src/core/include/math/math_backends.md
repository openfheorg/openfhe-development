# Math Backends

- By selecting a particular `MATHBACKEND`, we are choosing a default implementation for:
    - `BigInteger`
    - `BigVector`
    - `Poly` and `ciphertext modulus` used in `DCRTPoly`

- For native arithmetic, `NativeInteger` and `NativeVector` is available.

- All implementations for Big/Native Integer/Vector are based on [integer.h](integer.h).

## Design

**Goal**: Support choosing, at **run-time**, which math backend to use.

**Currently**: **Compile-time** choice of which backend to use

## Choosing a Backend

You can do either:

- Add a flag during the `CMAKE` process:` cmake -DMATHBACKEND=4 ..`
- Uncomment the appropriate line in `src/core/math/hal/bigintbackend.h` (and comment out the rest)

## Math Backend Descriptions

### MATHBACKEND 2

- Max size of `BigInteger` will be `BitIntegerBitLength` (defined in `backend.h) which has a default of 3000 bits.
- It is advisable to select a value for `BigIntegerBitLength` larger than double the `bitwidth` of the largest (
  ciphertext) modulus.
- This parameter can be decreased for runtime/space optimization when the largest modulus is under 1500 bits.

- **Note**: The underlying implementation is fixed-size array of native ints.
    - Native integer used is defined by the `typedef` using `integral_dtype` and MUST be `uint32_t`; using other types
      is an open work item

### MATHBACKEND 4

- No Explicit max size of `BigInteger`
- Size grows dynamically and is only constrained by memory
- The implementation requires that `UBINT_32` is defined as is in `ubintdyn.h`
- **Note**: Setting `UBINT_64` is not supported. It is however a open work item.

### MATHBACKEND 6

- Integration of `NTL` library with `OpenFHE`
- Only available when `NTL` or `GMP` is enabled using `CMAKE`

This is an integration of the NTL library with OpenFHE, and is only available when NTL/GMP is enabled using CMAKE.

# Supported Math Operations

## Modular Multiplication

We use the following naming conventions:

- `ModMul(b, mod)`
    - Naive modular multiplication that uses % operator for modular reduction
    - usually slow.

- `ModMul(b, mod, mu)`
    - Barrett modular multiplication. `mu` for Barrett modulo can be precomputed by `mod.ComputeMu()`.

- `ModMulFast(b, mod)`
    - Naive modular multiplication w/ operands < mod

- `ModMulFast(b, mod, mu)`
    - Barrett modular multiplication w/ operands < mod

- `ModMulFastConst(b, mod, bPrecomp)`
    - modular multiplication using precomputed information on b, w/ operands < mod.
    - `bPrecomp` can be precomputed by `b.PrepModMulConst(mod)`.
    - This method is currently implemented only for NativeInteger class.
    - The fastest method.

## Other Modular Operations

| Variant | Naive          | Barrett            | Fast Naive         | Fast Barrett           | Fast Const                        |
|---------|----------------|--------------------|--------------------|------------------------|-----------------------------------|
| Mod     | Mod(mod)       | Mod(mod, mu)       | -                  | -                      | -                                 |
| ModAdd  | ModAdd(b, mod) | ModAdd(b, mod, mu) | ModAddFast(b, mod) | -                      | -                                 |
| ModSub  | ModSub(b, mod) | ModSub(b, mod, mu) | ModSubFast(b, mod) | -                      | -                                 |
| ModMul  | ModMul(b, mod) | ModMul(b, mod, mu) | ModMulFast(b, mod) | ModMulFast(b, mod, mu) | ModMulFastConst(b, mod, bPrecomp) |
