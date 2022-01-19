// @file constants.cpp
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2021, New Jersey Institute of Technology (NJIT)
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

#include "constants.h"
#include <ostream>

std::ostream &operator<<(std::ostream &s, PKESchemeFeature f) {
  switch (f) {
    case PKE:
      s << "PKE";
      break;
    case KEYSWITCH:
      s << "KEYSWITCH";
      break;
    case PRE:
      s << "PRE";
      break;
    case LEVELEDSHE:
      s << "LEVELEDSHE";
      break;
    case ADVANCEDSHE:
      s << "ADVANCEDSHE";
      break;
    case MULTIPARTY:
      s << "MULTIPARTY";
      break;
    case FHE:
      s << "FHE";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

std::ostream &operator<<(std::ostream &s, MODE m) {
  switch (m) {
    case RLWE:
      s << "RLWE";
      break;
    case OPTIMIZED:
      s << "OPTIMIZED";
      break;
    case SPARSE:
      s << "SPARSE";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

std::ostream &operator<<(std::ostream &s, RescalingTechnique t) {
  switch (t) {
    case FIXEDMANUAL:
      s << "FIXEDMANUAL";
      break;
    case FIXEDAUTO:
      s << "FIXEDAUTO";
      break;
    case FLEXIBLEAUTO:
      s << "FLEXIBLEAUTO";
      break;
    case NORESCALE:
      s << "NORESCALE";
      break;
    case INVALID_RS_TECHNIQUE:
      s << "INVALID_RS_TECHNIQUE";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

std::ostream &operator<<(std::ostream &s, KeySwitchTechnique t) {
  switch (t) {
    case BV:
      s << "BV";
      break;
    case HYBRID:
      s << "HYBRID";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

std::ostream &operator<<(std::ostream &s, EncryptionTechnique t) {
  switch (t) {
    case STANDARD:
      s << "STANDARD";
      break;
    case POVERQ:
      s << "POVERQ";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}

std::ostream &operator<<(std::ostream &s, MultiplicationTechnique t) {
  switch (t) {
    case BEHZ:
      s << "BEHZ";
      break;
    case HPSPOVERQ:
      s << "HPSPOVERQ";
      break;
    case HPSPOVERQLEVELED:
      s << "HPSPOVERQLEVELED";
      break;
    default:
      s << "UKNOWN";
      break;
  }
  return s;
}
