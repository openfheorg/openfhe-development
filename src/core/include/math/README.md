# OpenFHE Core Math

# Math Backends

Default type for `BigInteger` and `BigVector` in the library.

## Design

**Goal**: Support choosing, at **run-time**, which math backend to use.

**Currently**: **Compile-time** choice of which backend to use

## Choosing a Backend



## Math Backend Descriptions

### MATHBACKEND 2
### MATHBACKEND 4

- No Explicit max size of `BigInteger`
- Size grows dynamically and is only constrained by memory
- The implementation requires that `UBINT_32` is defined as is in `ubintdyn.h` 
- **Note**: Setting `UBINT_64` is not supported. It is however a open work item.

### MATHBACKEND 6

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
