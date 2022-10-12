//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================
#include "schemebase/base-pre.h"

#include "key/privatekey.h"
#include "key/publickey.h"
#include "cryptocontext.h"
#include "schemebase/base-pke.h"
#include "schemebase/base-scheme.h"
#include "math/matrix.h"
#include "lattice/dgsampling.h"

namespace lbcrypto {

template <class Element>
EvalKey<Element> PREBase<Element>::ReKeyGen(const PrivateKey<Element> oldPrivateKey,
                                            const PublicKey<Element> newPublicKey) const {
    auto algo = oldPrivateKey->GetCryptoContext()->GetScheme();
    return algo->KeySwitchGen(oldPrivateKey, newPublicKey);
}

template <class Element>
Ciphertext<Element> PREBase<Element>::ReEncrypt(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                                const PublicKey<Element> publicKey) const {

    auto algo = ciphertext->GetCryptoContext()->GetScheme();

    const auto cryptoParams = std::static_pointer_cast<CryptoParametersRNS>(ciphertext->GetCryptoParameters());
    auto elementParams = cryptoParams->GetElementParams();

    usint ringDimension = cryptoParams->GetElementParams()->GetRingDimension();
    usint r             = cryptoParams->GetDigitSize();
    auto qmodulus        = cryptoParams->GetElementParams()->GetModulus();
    double k = log2(qmodulus.ConvertToDouble());

    const DggType& floodingdist = cryptoParams->GetFloodingDiscreteGaussianGenerator();
    DggType dgg = cryptoParams->GetDiscreteGaussianGenerator();

    //const DggType& dgg = cryptoParams->GetTrapdoorDiscreteGaussianGenerator();
    
    Ciphertext<Element> result = ciphertext->Clone();
    std::vector<Element>& cv = result->GetElements();
    if (publicKey != nullptr) {
        std::shared_ptr<std::vector<Element>> ba = algo->EncryptZeroCore(publicKey, floodingdist);

        cv[0] += (*ba)[0];
        cv[1] += (*ba)[1];
    }

    std::cout << "before checking pre mode in base-pre.cpp: " << cryptoParams->GetPREMode() << std::endl;

    if (cryptoParams->GetPREMode() == TRAPDOOR_HRA) {
        
        //Get the standard deviation for discrete gaussian samping and standard deviation for trapdoor discrete gaussian
        auto rtilde = floodingdist.GetTrapdoorStd();

        std::cout << "rtilde: " << rtilde << std::endl;
        std::cout << "rsigma: " << floodingdist.GetStd() << std::endl;
        //G-sample y in the algorithm such g^ty = cv[1];
        Matrix<int64_t> zHatBBI([]() { return 0; }, k/r + 1, ringDimension);

        cv[1].SetFormat(Format::COEFFICIENT);
        std::cout << "before g-sampling" << std::endl;

        std::cout << "zahatbbi rows " << zHatBBI.GetRows() << std::endl;
        std::cout << "zahatbbi cols " << zHatBBI.GetCols() << std::endl;
        LatticeGaussSampUtility<Element>::GaussSampGqArbBase(cv[1], rtilde, k/r, qmodulus, pow(2,r), dgg, &zHatBBI);

        // Convert zHat from a matrix of integers to a vector of Element ring elements
        // zHat is in the coefficient representation
        //Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, ringDimension, cv[1].GetParams());

        std::cout << "before split64 k/r value " << k/r << std::endl;
        Matrix<Element> zHat = SplitInt64AltIntoElements<Element>(zHatBBI, k/r, cv[1].GetParams());

        // Now converting it to a vector and the Format::EVALUATION representation before
        // reencryption
        std::vector<Element> y;
        std::cout << "zhat rows " << zHat.GetRows() << std::endl;
        std::cout << "zhat cols " << zHat.GetCols() << std::endl;
        //convert matrix to vector to pass as argument to EvalFastKeySwitchCore
        for (size_t i = 0; i < zHat.GetRows(); i++ ) {
            y.push_back(zHat(i,0));
            y[i].SetFormat(Format::EVALUATION);
        }

        std::cout << "y size " << y.size() << std::endl;
        
        //verify that gadget g^t.y = cv[1]
        std::vector<Element> ctcheck;
        //auto zparams     = std::make_shared<ILParams>(2*ringDimension, qmodulus, elementParams->GetRootOfUnity());
        auto zero_alloc = Element::Allocator(elementParams, EVALUATION);
        Matrix<Element> g = Matrix<Element>(zero_alloc, 1, k).GadgetVector(r);
        for (size_t i = 0; i < y.size(); i++ ) {
            ctcheck.push_back(g(0, i) * y[i]);
            std::cout << "g[i]" << g(0,i) << std::endl;    
            std::cout << "ctcheck[i]" << ctcheck[i] << std::endl;
        }
        std::cout << "cv[1]" << cv[1] << std::endl;


        std::cout << "before shared_ptr" << std::endl;
        
        std::shared_ptr<std::vector<Element>> yp;
        {
            yp = std::make_shared<std::vector<Element>>(std::move(y));
        }

        //sample z as discrete gaussian of width r
        DCRTPoly z(floodingdist, elementParams, Format::EVALUATION);

        //compute the reencryption (same operations as keyswitchcore function in keyswitch-bv.cpp but with the sampled y instead of ciphertext cv)
        const auto cryptoParamsBase = evalKey->GetCryptoParameters();

        std::cout << "before evalfastkeyswitchcore" << std::endl;
        std::shared_ptr<std::vector<Element>> digits = algo->EvalKeySwitchPrecomputeCore(cv[1], cryptoParamsBase);
        std::shared_ptr<std::vector<Element>> ba = algo->EvalFastKeySwitchCore(digits, evalKey, cv[1].GetParams());

        //std::shared_ptr<std::vector<Element>> ba = algo->EvalFastKeySwitchCore(yp, evalKey, cv[1].GetParams());
        
        std::cout << "after evalfastkeyswitchcore" << std::endl;

        //cv[0].SetFormat(Format::EVALUATION);
        
        //compute c*_b as rk_b*y + cv[0] + pz
        cv[0] += (*ba)[0];
        cv[0] += z;

        cv[1] = (*ba)[1];
        std::cout << "after all compute" << std::endl;

    } else {
        algo->KeySwitchInPlace(result, evalKey);
    }

    return result;
}

}  // namespace lbcrypto

// the code below is from base-pre-impl.cpp
namespace lbcrypto {

template class PREBase<DCRTPoly>;

}  // namespace lbcrypto
