// @file ciphertexthelper.h -- Helper for crypto contexts.
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

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_

#include <iostream>
#include <string>

#include "cryptocontext.h"
#include "cryptocontextparametersets.h"

namespace lbcrypto {

class CryptoContextHelper {
 public:
  /**
   *
   * @param out stream to write to
   */
  static void printAllParmSets(std::ostream& out);

  /**
   *
   * @param out stream to write to
   * @param parmset parameter set name
   */
  static void printParmSet(std::ostream& out, string parmset);

  /**
   *
   * @param out stream to write to
   */
  static void printAllParmSetNames(std::ostream& out);

  /**
   * Prints all parameter sets matching the filter
   *
   * @param out stream to write to
   * @param filter is a substring that matches parameter set names
   */
  static void printParmSetNamesByFilter(std::ostream& out,
                                        const string& filter);

  /**
   * Prints all parameter sets matching one of the filters
   *
   * @param out stream to write to
   * @param filters is a list of substrings that matches parameter set names
   */
  static void printParmSetNamesByFilters(
      std::ostream& out, std::initializer_list<std::string> filters);

  /**
   * Prints all parameter sets excluding the ones matching the filter
   *
   * @param out stream to write to
   * @param filter is a substring that matches parameter set names
   */
  static void printParmSetNamesByExcludeFilter(std::ostream& out,
                                               const string& filter);

  /**
   * Prints all parameter sets excluding the ones matching one of the filters
   *
   * @param out stream to write to
   * @param filters a list of substrings that matches parameter set names
   */
  static void printParmSetNamesByExcludeFilters(
      std::ostream& out, std::initializer_list<std::string> filters);

  /**
   * Generate a CryptoContext for a given parameter set name
   *
   * @param parmsetname name of parameter set to use
   * @return newly constructed CryptoContext, or null on failure
   */
  static CryptoContext<Poly> getNewContext(const string& parmsetname,
                                           EncodingParams p = 0);

  /**
   * Generate a DCRT CryptoContext for a given parameter set name
   *
   * @param parmsetname name of parameter set to use
   * @param numTowers - how many towers to generate
   * @param primeBits - bit width of the primes in the towers
   * @return newly constructed CryptoContext, or null on failure
   */
  static CryptoContext<DCRTPoly> getNewDCRTContext(const string& parmsetname,
                                                   usint numTowers,
                                                   usint primeBits);

  template <typename Element>
  static CryptoContext<Element> ContextFromAppProfile(const string& scheme,
                                                      PlaintextModulus ptm,
                                                      usint nA, usint nM,
                                                      usint nK, usint maxD,
                                                      float secFactor);
};

}  // namespace lbcrypto

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_ */
