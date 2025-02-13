#include <iostream>
#include <chrono>

#include "openfhecore.h"
using namespace lbcrypto;

// This code benchmarks the NTT/INTT functionality in OpenFHE
// NTT and INTT implementation in OpenFHE are based on this work: https://eprint.iacr.org/2016/504
// The implementation of NTT can be found here : https://github.com/openfheorg/openfhe-development/blob/v1.2.3/src/core/include/math/hal/intnat/transformnat-impl.h#L302
// The implementation of INTT can be found here: https://github.com/openfheorg/openfhe-development/blob/v1.2.3/src/core/include/math/hal/intnat/transformnat-impl.h#L511
 
// size in bits of the RNS moduli, 60 bits here
constexpr uint32_t DCRTBITS = 60;

int main() {
  std::cout << "NTT Benchmark started ...\n";

  // define a discrete uniform random number generator to populate the polynomial
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  
  // Define the ring dimension N = 2^{logN}
  // Test for logN = 10, 11, ... , 16 (and if supported, 17 as well)
  uint32_t logN = 5; 

  // define native integer parameters
  // note that ILNativeParams takes as input the order m = 2*n
  auto params = std::make_shared<ILNativeParams>(1 << (logN + 1), DCRTBITS);

  std::cout << "ring dimension     : " << params->GetRingDimension() << "\n";
  std::cout << "prime modulus      : " << params->GetModulus() << "\n";
  std::cout << "m-th root of unity : " << params->GetRootOfUnity() << "\n";
  
  // create a random polynomial in coefficient representation
  auto poly = NativePoly(dug, params, Format::COEFFICIENT);
  std::cout << "poly: " << poly << std::endl;

  const uint32_t num_iterations = 1000;  // Number of iterations for benchmarking
  
  // Accumulated time
  long long forward_time = 0;
  long long inverse_time = 0;

  for (size_t i = 0; i < num_iterations; ++i) {
    
    auto start_forward = std::chrono::high_resolution_clock::now();
    // call NTT transforms
    poly.SwitchFormat();  // forward ntt
    auto end_forward = std::chrono::high_resolution_clock::now();
    forward_time += std::chrono::duration_cast<std::chrono::microseconds>(end_forward - start_forward).count();
    if (0 == i)
      std::cout << "poly: " << poly << std::endl;

    auto start_inverse = std::chrono::high_resolution_clock::now();
    poly.SwitchFormat();  // inverse ntt
    auto end_inverse = std::chrono::high_resolution_clock::now();
    inverse_time += std::chrono::duration_cast<std::chrono::microseconds>(end_inverse - start_inverse).count();
    
    if (0 == i)
      std::cout << "poly: " << poly << std::endl;
  }

  // Calculate average time
  double avg_forward_time = static_cast<double>(forward_time) / num_iterations;
  double avg_inverse_time = static_cast<double>(inverse_time) / num_iterations;

  // Output the results
  std::cout << "Average time for forward NTT: " << avg_forward_time << " microseconds" << std::endl;
  std::cout << "Average time for inverse NTT: " << avg_inverse_time << " microseconds" << std::endl;

  std::cout << "NTT Benchmark terminated gracefully.\n";
  
  return EXIT_SUCCESS;
}
