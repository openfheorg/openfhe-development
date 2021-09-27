/** @file hexldcrtpoly.cpp
 *
 * @brief test file for checking if the interface class is
 * implemented correctly Intel HEXL specific DCRT Polynomial Object
 * 
 * @author TPOC: contact@palisade-crypto.org
 * 
 * @contributor Jonathan Saylor (jsaylor@dualitytech.com)
 * 
 * @copyright Copyright (c) 2021, Duality Technologies (https://dualitytech.com/)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. THIS SOFTWARE IS
 * PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#if defined(WITH_INTEL_HEXL)

#include <fstream>
#include <memory>

#include "hexl/hexl.hpp"

#include "math/backend.h"
#include "lattice/hexldcrtpoly.h"
#include "utils/debug.h"

using std::shared_ptr;
using std::string;

namespace lbcrypto {

// used for CKKS rescaling
template<typename VecType>
void HexlDCRTPoly<VecType>::DropLastElementAndScale(
   const std::vector<NativeInteger> &QlQlInvModqlDivqlModq,
   const std::vector<NativeInteger> &QlQlInvModqlDivqlModqPrecon,
   const std::vector<NativeInteger> &qlInvModq,
   const std::vector<NativeInteger> &qlInvModqPrecon) {
 usint sizeQl = this->m_vectors.size();

 // last tower that will be dropped
 PolyType lastPoly(this->m_vectors[sizeQl - 1]);

 // drop the last tower
 this->DropLastElement();

 lastPoly.SetFormat(Format::COEFFICIENT);
 HexlDCRTPoly extra(this->m_params, COEFFICIENT, true);

#pragma omp parallel for
 for (usint i = 0; i < extra.m_vectors.size(); i++) {
   auto temp = lastPoly;
   temp.SwitchModulus(this->m_vectors[i].GetModulus(),
                      this->m_vectors[i].GetRootOfUnity());
   extra.m_vectors[i] = (temp *= QlQlInvModqlDivqlModq[i]);
 } // omp threaded loop

 if (this->GetFormat() == Format::EVALUATION)
   extra.SetFormat(Format::EVALUATION);

 usint ringDim = this->GetRingDimension();
 for (usint i = 0; i < this->m_vectors.size(); i++) {
   const NativeInteger &qi = this->m_vectors[i].GetModulus();
   PolyType &m_veci = this->m_vectors[i];
   PolyType &extra_m_veci = extra.m_vectors[i];
   const auto multOp = qlInvModq[i];
   uint64_t *op1 = reinterpret_cast<uint64_t *>(&m_veci[0]);
   uint64_t op2 = multOp.ConvertToInt();
   uint64_t *op3 = reinterpret_cast<uint64_t *>(&extra_m_veci[0]);
   intel::hexl::EltwiseFMAMod(op1, op1, op2, op3, ringDim, qi.ConvertToInt(),
                              1);
 }

 this->SetFormat(Format::EVALUATION);
} // DCRTPolyImpl<VecType>::DropLastElementAndScale

} // namespace lbcrypto

#endif // WITH_INTEL_HEXL