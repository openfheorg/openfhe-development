OpenFHE Library - CKKS Composite Scaling
=====================================================================================================

CKKS Composite Scaling enables high-precision RNS-CKKS when the hardware architecture word size is smaller than the scaling factor. The algorithms are described in [https://eprint.iacr.org/2023/1462.pdf](https://eprint.iacr.org/2023/1462.pdf). The code was contributed by Intel Labs.

## Overview of CKKS Composite Scaling

CKKS composite scaling is designed to achieve high-precision RNS-CKKS encrypted computation with scaling factors greater than the target hardware architecture's register word size. For example, with composite scaling, we can configure the RNS scaling factor to be 58 bits, i.e. choosing prime moduli with 58 bits of precision, and compute on an accelerator whose architecture's register size is 32 bits. This feature is introduced into the OpenFHE API as a new scaling technique.

## Composite Modulus Chain Generation

- All prime moduli are NTT-friendly (tested up to $2^{16}$).
- All primes in the modulus chain are distinct from each other.

- $q_i = p_1 \times \cdots \times p_d \approx 2^\Delta$, where $\Delta$ is the scaling factor ($\log \Delta$ is the `scalingModSize` in OpenFHE), $q_i$ is the composite coefficient modulus comprised of the prime moduli ${p_1, \cdots, p_d}$, and $d$ is the composite degree that characterizes the composite scaling approach.

- $p_i$ is chosen to be very close $2^{\log \Delta / d }$.

## How to Use Composite Scaling:

- By setting the scaling technique to COMPOSITESCALINGAUTO: This is the most suitable choice for any developer trying out or not familiar with the intricate details of composite scaling.

- The register word size can be set using `SetRegisterWordSize`, e.g., to 32 or 64. The supported range is 20 to 64. This limits the maximum size of the (small) moduli used to represent the scaling factor in composite-scaling CKKS. The default value is 32.

- Alternatively, the scaling technique can be set to COMPOSITESCALINGMANUAL: This mode is meant for developers/FHE experts that wish to experiment with untested/unlikely combinations of composite scaling parameters that may only be functional under special circumstances. In those special cases, the program may be more sensitive to runtime errors due to insufficient availability of prime moduli for given certain values for the tuple <register word size, multiplicative depth, ring size>.

   - The composite degree can be set using `SetCompositeDegree`, e.g., to 2, 3, or 4. This defines how many small moduli should be used to represent the scaling factor. This setting is only supported for COMPOSITESCALINGMANUAL.

## Composite Scaling Bootstrapping

- Current implementation supports single-iteration CKKS bootstrapping.

- Current implementation supports Meta-BTS (or multiple-iteration) CKKS bootstrapping.

## Current Constraints

- This current CKKS composite scaling implementation only supports single-key CKKS. In other words, multiparty (threshold) CKKS and scheme switching are not supported yet.

- By design, when operating on composite scaling mode (i.e., COMPOSITESCALINGAUTO), the target hardware platform is assumed to have a fixed word size smaller than 64 bits. However, it still works when CKKS scaling factors are greater than 64 bits, even on hardware architectures with 64-bit register word sizes. The latter is a more efficient alternative to using NATIVE_SIZE=128 in scenarios when $IND-CPA^D$ security or high precision needs to be achieved.

- Regardless of the target architecture word size, the OpenFHE library needs to be compiled using the NATIVE_SIZE=64 compilation flag. In other words, NATIVE_SIZE=32 is not supported.

- COMPOSITESCALING<AUTO/MANUAL> scaling technique mode only works with the CKKS scheme.

## Examples

- [iterative-ckks-bootstrapping-composite-scaling.cpp](iterative-ckks-bootstrapping-composite-scaling.cpp): Double-precision CKKS bootstrapping in the CKKS composite scaling mode.
- [polynomial-evaluation-high-precision-composite-scaling.cpp](polynomial-evaluation-high-precision-composite-scaling.cpp): High-precision (80-bit scaling factor) power series evaluation in the CKKS composite scaling mode.
- [simple-ckks-bootstrapping-composite-scaling.cpp](simple-ckks-bootstrapping-composite-scaling.cpp): Single-precision CKKS bootstrapping in the CKKS composite scaling mode.
- [simple-real-numbers-composite-scaling.cpp](simple-real-numbers-composite-scaling.cpp): Basic CKKS arithmetic in the CKKS composite scaling mode.
