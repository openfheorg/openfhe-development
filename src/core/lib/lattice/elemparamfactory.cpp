// @file elemparamfactory.cpp - constructs element parameters
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

#include "lattice/elemparamfactory.h"

namespace lbcrypto {

struct ElemParamFactory::ElemParmSet ElemParamFactory::DefaultSet[] = {
    {16, 8, "1099511627873", "108163207722"},
    {1024, 512, "525313", "513496"},
    {2048, 1024,
     "34359724033",  // (1<<35) - (1<<14) + (1<<11) + 1
     "7225104974"},
    {4096, 2048,
     "1152921504606830593",  // (1<<60) - (1<<14) + 1
     "811032584449645127"},
    {8192, 4096,
     "83076749736557242056487941267259393",  // (1<<116) - (1<<18) + 1
     "37599714064159745447475925700289107"},
    {16384, 8192,
     "10783978666860255917866806034807852269454857769016228992441437388800"
     "1",  // (1<<226) - (1<<26) + 1
     "1140011778039787407297219888956424090702191858213752597552584341505"
     "3"},
    {32768, 16384,  // (1<<435) - (1<<33) + 1
     "887254302118660755065092538925786785099659864120261304054553465796678"
     "81849780019937279180995332466499116518750764914298518583115777",
     "246067649222497136789709483599549969960973934446743502013340482728572"
     "96990709662751965279696328118503540981820164645549732655298796"},
    {0, 0, "", ""}  // endmarker
};

} /* namespace lbcrypto */
