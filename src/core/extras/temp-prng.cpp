// @file TODO
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "palisadecore.h"
#include "utils/parallel.h"

using namespace lbcrypto;

void DieHarder();
void UniformGenerator();

int main() {
  // DieHarder();
  UniformGenerator();

  return 0;
}

void UniformGenerator() {
  auto distrUniGen = DiscreteUniformGeneratorImpl<NativeVector>();
  distrUniGen.SetModulus(NativeInteger((uint64_t)1 << 59));

  uint32_t nthreads = ParallelControls().GetMachineThreads();

  std::cout << "number of threads: " << nthreads << std::endl;

  std::vector<NativeVector> vec(nthreads);

#pragma omp parallel for
  for (uint32_t i = 0; i < nthreads; i++) {
    vec[i] = distrUniGen.GenerateVector(8);
  }

  for (uint32_t i = 0; i < nthreads; i++) {
    std::cout << "vector " << i << " " << vec[i] << std::endl;
  }
}

void DieHarder() {
  std::ofstream myfile;
  myfile.open("out.bin", std::ios::out | std::ios::binary);
  for (size_t i = 0; i < 10000000; i++) {
    uint32_t sample = PseudoRandomNumberGenerator::GetPRNG()();
    // std::cout << sample << std::endl;
    myfile.write(reinterpret_cast<char*>(&sample), sizeof(uint32_t));
  }
  myfile.close();
}
