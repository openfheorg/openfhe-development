// @file stdlatticeparms.cpp: Implementation for the standard values for Lattice
// Parms, as determined by homomorphicencryption.org
//
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

#include <vector>
#include "lattice/stdlatticeparms.h"
using std::vector;

namespace lbcrypto {

map<usint, StdLatticeParm*> StdLatticeParm::byRing[3][3];
map<usint, StdLatticeParm*> StdLatticeParm::byLogQ[3][3];

bool StdLatticeParm::initialized = false;

// this is a collection of all of the parameter sets
// the constructor for each one saves and indexes it so that you can search for
// it with static methods in the StdLatticeParm class
vector<StdLatticeParm> StdLatticeParm::StandardLatticeParmSets({
    StdLatticeParm(HEStd_uniform, 1024, HEStd_128_classic, 29),
    StdLatticeParm(HEStd_uniform, 1024, HEStd_192_classic, 21),
    StdLatticeParm(HEStd_uniform, 1024, HEStd_256_classic, 16),
    StdLatticeParm(HEStd_uniform, 2048, HEStd_128_classic, 56),
    StdLatticeParm(HEStd_uniform, 2048, HEStd_192_classic, 39),
    StdLatticeParm(HEStd_uniform, 2048, HEStd_256_classic, 31),
    StdLatticeParm(HEStd_uniform, 4096, HEStd_128_classic, 111),
    StdLatticeParm(HEStd_uniform, 4096, HEStd_192_classic, 77),
    StdLatticeParm(HEStd_uniform, 4096, HEStd_256_classic, 60),
    StdLatticeParm(HEStd_uniform, 8192, HEStd_128_classic, 220),
    StdLatticeParm(HEStd_uniform, 8192, HEStd_192_classic, 154),
    StdLatticeParm(HEStd_uniform, 8192, HEStd_256_classic, 120),
    StdLatticeParm(HEStd_uniform, 16384, HEStd_128_classic, 440),
    StdLatticeParm(HEStd_uniform, 16384, HEStd_192_classic, 307),
    StdLatticeParm(HEStd_uniform, 16384, HEStd_256_classic, 239),
    StdLatticeParm(HEStd_uniform, 32768, HEStd_128_classic, 880),
    StdLatticeParm(HEStd_uniform, 32768, HEStd_192_classic, 612),
    StdLatticeParm(HEStd_uniform, 32768, HEStd_256_classic, 478),

    StdLatticeParm(HEStd_error, 1024, HEStd_128_classic, 29),
    StdLatticeParm(HEStd_error, 1024, HEStd_192_classic, 21),
    StdLatticeParm(HEStd_error, 1024, HEStd_256_classic, 16),
    StdLatticeParm(HEStd_error, 2048, HEStd_128_classic, 56),
    StdLatticeParm(HEStd_error, 2048, HEStd_192_classic, 39),
    StdLatticeParm(HEStd_error, 2048, HEStd_256_classic, 31),
    StdLatticeParm(HEStd_error, 4096, HEStd_128_classic, 111),
    StdLatticeParm(HEStd_error, 4096, HEStd_192_classic, 77),
    StdLatticeParm(HEStd_error, 4096, HEStd_256_classic, 60),
    StdLatticeParm(HEStd_error, 8192, HEStd_128_classic, 220),
    StdLatticeParm(HEStd_error, 8192, HEStd_192_classic, 154),
    StdLatticeParm(HEStd_error, 8192, HEStd_256_classic, 120),
    StdLatticeParm(HEStd_error, 16384, HEStd_128_classic, 440),
    StdLatticeParm(HEStd_error, 16384, HEStd_192_classic, 307),
    StdLatticeParm(HEStd_error, 16384, HEStd_256_classic, 239),
    StdLatticeParm(HEStd_error, 32768, HEStd_128_classic, 883),
    StdLatticeParm(HEStd_error, 32768, HEStd_192_classic, 613),
    StdLatticeParm(HEStd_error, 32768, HEStd_256_classic, 478),

    StdLatticeParm(HEStd_ternary, 1024, HEStd_128_classic, 27),
    StdLatticeParm(HEStd_ternary, 1024, HEStd_192_classic, 19),
    StdLatticeParm(HEStd_ternary, 1024, HEStd_256_classic, 14),
    StdLatticeParm(HEStd_ternary, 2048, HEStd_128_classic, 54),
    StdLatticeParm(HEStd_ternary, 2048, HEStd_192_classic, 37),
    StdLatticeParm(HEStd_ternary, 2048, HEStd_256_classic, 29),
    StdLatticeParm(HEStd_ternary, 4096, HEStd_128_classic, 109),
    StdLatticeParm(HEStd_ternary, 4096, HEStd_192_classic, 75),
    StdLatticeParm(HEStd_ternary, 4096, HEStd_256_classic, 58),
    StdLatticeParm(HEStd_ternary, 8192, HEStd_128_classic, 218),
    StdLatticeParm(HEStd_ternary, 8192, HEStd_192_classic, 152),
    StdLatticeParm(HEStd_ternary, 8192, HEStd_256_classic, 118),
    StdLatticeParm(HEStd_ternary, 16384, HEStd_128_classic, 438),
    StdLatticeParm(HEStd_ternary, 16384, HEStd_192_classic, 305),
    StdLatticeParm(HEStd_ternary, 16384, HEStd_256_classic, 237),
    StdLatticeParm(HEStd_ternary, 32768, HEStd_128_classic, 881),
    StdLatticeParm(HEStd_ternary, 32768, HEStd_192_classic, 611),
    StdLatticeParm(HEStd_ternary, 32768, HEStd_256_classic, 476),
});

} /* namespace lbcrypto */
