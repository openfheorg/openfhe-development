// @file cryptocontextparametersets-impl.cpp - cryptocontext parameter sets
// implementation
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

#include "cryptocontextparametersets.h"

namespace lbcrypto {

map<string, map<string, string>> CryptoContextParameterSets = {
    {"BFV1",
     {
         {"parameters", "BFV"},
         {"plaintextModulus", "4"},
         {"securityLevel", "1.006"},
     }},

    {"BFV2",
     {{"parameters", "BFV"},
      {"plaintextModulus", "16"},
      {"securityLevel", "1.006"}}},

    {"BFVrns1",
     {
         {"parameters", "BFVrns"},
         {"plaintextModulus", "4"},
         {"securityLevel", "1.006"},
     }},

    {"BFVrns2",
     {{"parameters", "BFVrns"},
      {"plaintextModulus", "16"},
      {"securityLevel", "1.006"}}},

    {"BFVrnsB1",
     {
         {"parameters", "BFVrnsB"},
         {"plaintextModulus", "4"},
         {"securityLevel", "1.006"},
     }},

    {"BFVrnsB2",
     {{"parameters", "BFVrnsB"},
      {"plaintextModulus", "16"},
      {"securityLevel", "1.006"}}},

    {"Null",
     {{"parameters", "Null"},
      {"plaintextModulus", "256"},
      {"ring", "8192"},
      {"modulus", "256"},
      {"rootOfUnity", "242542334"}}},

    {"Null2",
     {{"parameters", "Null"},
      {"plaintextModulus", "5"},
      {"ring", "32"},
      {"modulus", "256"},
      {"rootOfUnity", "322299632"}}},
    {"BFV-PRE",
     {{"parameters", "BFV"},
      {"plaintextModulus", "2"},
      {"securityLevel", "1.006"}}},
    {"Null-PRE",
     {{"parameters", "Null"},
      {"plaintextModulus", "2"},
      {"ring", "2048"},
      {"modulus", "2"},
      {"rootOfUnity", "1"}}}};

} /* namespace lbcrypto */
