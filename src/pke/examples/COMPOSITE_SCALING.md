OpenFHE Library - CKKS Composite Scaling
=====================================================================================================

CKKS Composite Scaling enables high-precision RNS-CKKS when the hardware architecture word size is smaller than the scaling factor. The algorithms are described in [https://eprint.iacr.org/2023/1462.pdf](https://eprint.iacr.org/2023/1462.pdf). The code was contributed by Intel Labs.

## Overview of CKKS Composite Scaling

CKKS composite scaling is designed to achieve high-precision RNS-CKKS encrypted computation with scaling factors greater than the target hardware architecture's register word size. For example, with composite scaling, we can configure the RNS scaling factor to be 58 bits, i.e. choosing prime moduli with 58 bits of precision, and compute on an accelerator whose architecture's register size is 32 bits. This feature is introduced into the OpenFHE API as a new scaling technique.

## How to Use Composite Scaling:

- By setting the scaling technique to COMPOSITESCALINGAUTO: This is the most suitable choice for any developer trying out or not familiar with the intricate details of composite scaling.

- By setting the scaling technique to COMPOSITESCALINGMANUAL: This mode is meant for developers/FHE experts that wish to experiment with untested/unlikely combinations of composite scaling parameters that may only be functional under special circumstances. In those special cases, the program may be more sensitive to runtime errors due to insufficient availability of prime moduli for given certain values for the tuple <register word size, multiplicative depth, ring size>.

## Composite Modulus Chain Generation

- All prime moduli are NTT-friendly (tested up to 2^16).
- All primes in the modulus chain are distinct from each other.

- `q_i = p_1 x ... x p_ d ~ 2 ^\delta`, where `\delta` is the scaling factor, `q_i` is the composite coefficient modulus comprised of the prime moduli `{p_1, ..., p_d}`, and `d` is the composite degree that characterizes the composite scaling approach.

- `p_i` is chosen to be very close `2^( (scalingModSize) / (composite degree) )`

## Composite Scaling Bootstrapping

- Current implementation supports single-iteration CKKS bootstrapping.

- Current implementation supports Meta-BTS (or multiple-iteration) CKKS bootstrapping.

## Current Constraints

- This current CKKS composite scaling implementation only supports single-key CKKS. In other words, multiparty (threshold) CKKS and scheme switching are not supported yet.

- By design when operating on composite scaling mode (i.e., COMPOSITESCALINGAUTO), the target hardware platform is assumed to have fixed word size smaller than 64 bits. However, in general, it still works under the scenario where scaling factors greater than 64 bits running on hardware architectures having 64-bit register word size.

- Regardless of the target architecture word size, the OpenFHE library needs to be compiled using NATIVE_SIZE=64 compilation flag. In other words, NATIVE_SZIE=32 is not supported.

- COMPOSITESCALING<AUTO/MANUAL> scaling technique mode only works with the CKKS scheme.
