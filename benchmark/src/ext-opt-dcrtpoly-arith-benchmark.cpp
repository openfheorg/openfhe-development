#include <iostream>
#include <chrono>

#include "openfhecore.h"
using namespace lbcrypto;

// This code benchmarks polynomial arithmetic in OpenFHE
// we are showing here three benchmarks:
// 1. coordinate-wise polynomial addition,
// 2. coordinate-wise polynomial multiplication, and
// 3. polynomial times constant (coordinate-wise multiplication by a constant)
// all operations are done in the NTT domain (EVAL Format), meaning, both operand polys should be in the NTT format
// the result is also in the NTT format

// The implementation of these arithmetic operations can be found here:
// DCRTPoly-DCRTPoly Add : https://github.com/openfheorg/openfhe-development/blob/v1.2.3/src/core/include/lattice/hal/default/dcrtpoly.h#L153
// DCRTPoly-DCRTPoly Mul : https://github.com/openfheorg/openfhe-development/blob/v1.2.3/src/core/include/lattice/hal/default/dcrtpoly.h#L174
// DCRTPoly-Const Mul: https://github.com/openfheorg/openfhe-development/blob/v1.2.3/src/core/include/lattice/hal/default/dcrtpoly-impl.h#L573

// size in bits of the RNS moduli, 60 bits here
constexpr uint32_t DCRTBITS = 60;

int main() {
    std::cout << "DCRT Poly Arithmetic Benchmark started ...\n";

    // define a discrete uniform random number generator to populate the polynomial
    DiscreteUniformGeneratorImpl<NativeVector> dug;

    // Define the ring dimension N = 2^{logN}
    // Test for logN = 10, 11, ... , 16 (and if supported, 17 as well)
    uint32_t logN = 5;
    uint32_t num_limbs = 3;

    // define native integer parameters
    // note that ILDCRTParams takes as input the order m = 2*n
    auto params = std::make_shared<ILDCRTParams<BigInteger>>(1 << (logN + 1), num_limbs, DCRTBITS);

    std::cout << "ring dimension    : " << params->GetRingDimension() << "\n";
    std::cout << "prime modulus     : " << params->GetModulus() << "\n";
    std::cout << "BigModulus modulus: " << params->GetBigModulus() << "\n";
    std::cout << "number of limbs   : " << params->GetParams().size() << "\n";

    // create a random polynomial in coefficient representation
    DCRTPoly dcrtpoly1(dug, params, Format::EVALUATION);
    DCRTPoly dcrtpoly2(dug, params, Format::EVALUATION);
    auto constFactor = NativeInteger(dug.GenerateInteger());

    std::cout << "dcrtpoly1: " << dcrtpoly1 << std::endl;
    std::cout << "dcrtpoly2: " << dcrtpoly2 << std::endl;
    std::cout << "const    : " << constFactor << std::endl;

    const uint32_t num_iterations = 1000;  // Number of iterations for benchmarking

    // Accumulated time
    long long add_time  = 0;
    long long mul_time  = 0;
    long long mulc_time = 0;

    for (size_t i = 0; i < num_iterations; ++i) {
        auto start_sum = std::chrono::high_resolution_clock::now();
        auto sum       = dcrtpoly1 + dcrtpoly2;
        auto end_sum   = std::chrono::high_resolution_clock::now();
        add_time += std::chrono::duration_cast<std::chrono::microseconds>(end_sum - start_sum).count();
        if (0 == i)
            std::cout << "sum: " << sum << std::endl;

        auto start_mul = std::chrono::high_resolution_clock::now();
        auto mul       = dcrtpoly1 * dcrtpoly2;  // inverse ntt
        auto end_mul   = std::chrono::high_resolution_clock::now();
        mul_time += std::chrono::duration_cast<std::chrono::microseconds>(end_mul - start_mul).count();
        if (0 == i)
            std::cout << "mul: " << mul << std::endl;

        auto start_mulc = std::chrono::high_resolution_clock::now();
        auto mulConst   = dcrtpoly1 * constFactor;
        auto end_mulc   = std::chrono::high_resolution_clock::now();
        mulc_time += std::chrono::duration_cast<std::chrono::microseconds>(end_mulc - start_mulc).count();
        if (0 == i)
            std::cout << "mulConst: " << mulConst << std::endl;
    }

    // Calculate average time
    double avg_add_time  = static_cast<double>(add_time) / num_iterations;
    double avg_mul_time  = static_cast<double>(mul_time) / num_iterations;
    double avg_mulc_time = static_cast<double>(mulc_time) / num_iterations;

    // Output the results
    std::cout << "Average time for adding 2 dcrtpolys     : " << avg_add_time << " microseconds" << std::endl;
    std::cout << "Average time for multiplying 2 dcrtpolys: " << avg_mul_time << " microseconds" << std::endl;
    std::cout << "Average time for dcrtpoly Mult Const    : " << avg_mulc_time << " microseconds" << std::endl;

    std::cout << "DCRT Poly Arithmetic Benchmark terminated gracefully.\n";

    return EXIT_SUCCESS;
}
