// @file stringencoding.h Represents and defines string-encoded plaintext
// objects in Palisade.
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

#ifndef SRC_CORE_LIB_ENCODING_STRINGENCODING_H_
#define SRC_CORE_LIB_ENCODING_STRINGENCODING_H_

#include <memory>
#include <string>

#include "encoding/plaintext.h"
using std::string;

namespace lbcrypto {

class StringEncoding : public PlaintextImpl {
  string ptx;
  // enum EncodingType { CHAR7bit } encoding = CHAR7bit;

 public:
  // these three constructors are used inside of Decrypt
  StringEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {}

  StringEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {}

  StringEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep)
      : PlaintextImpl(vp, ep) {}

  StringEncoding(shared_ptr<Poly::Params> vp, EncodingParams ep, string str)
      : PlaintextImpl(vp, ep), ptx(str) {}

  StringEncoding(shared_ptr<NativePoly::Params> vp, EncodingParams ep,
                 string str)
      : PlaintextImpl(vp, ep), ptx(str) {}

  StringEncoding(shared_ptr<DCRTPoly::Params> vp, EncodingParams ep, string str)
      : PlaintextImpl(vp, ep), ptx(str) {}

  // TODO provide wide-character version (for unicode); right now this class
  // only supports strings of 7-bit ASCII characters

  virtual ~StringEncoding() {}

  /**
   * GetStringValue
   * @return the un-encoded string
   */
  const string& GetStringValue() const { return ptx; }

  /**
   * SetStringValue
   * @param val to initialize the Plaintext
   */
  void SetStringValue(const std::string& value) { ptx = value; }

  /**
   * Encode the plaintext into the Poly
   * @return true on success
   */
  bool Encode();

  /**
   * Decode the Poly into the string
   * @return true on success
   */
  bool Decode();

  /**
   * GetEncodingType
   * @return this is a String encoding
   */
  PlaintextEncodings GetEncodingType() const { return String; }

  /**
   * Get length of the plaintext
   *
   * @return number of elements in this plaintext
   */
  size_t GetLength() const { return ptx.size(); }

  /**
   * Method to compare two plaintext to test for equivalence
   * Testing that the plaintexts are of the same type done in operator==
   *
   * @param other - the other plaintext to compare to.
   * @return whether the two plaintext are equivalent.
   */
  bool CompareTo(const PlaintextImpl& other) const {
    const auto& oth = static_cast<const StringEncoding&>(other);
    return oth.ptx == this->ptx;
  }

  /**
   * PrintValue - used by operator<< for this object
   * @param out
   */
  void PrintValue(std::ostream& out) const { out << ptx; }
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_STRINGENCODING_H_ */
