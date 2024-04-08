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

/*
  Represents and defines plaintext encodings in OpenFHE with bit packing capabilities
 */

#include "encoding/packedencoding.h"
#include "math/math-hal.h"
#include "utils/utilities.h"

namespace lbcrypto {

// TODO (dsuponit): we should not have globals!
std::map<ModulusM, NativeInteger> PackedEncoding::m_initRoot;
std::map<ModulusM, NativeInteger> PackedEncoding::m_bigModulus;
std::map<ModulusM, NativeInteger> PackedEncoding::m_bigRoot;

std::map<usint, usint> PackedEncoding::m_automorphismGenerator;
std::map<usint, std::vector<usint>> PackedEncoding::m_toCRTPerm;
std::map<usint, std::vector<usint>> PackedEncoding::m_fromCRTPerm;

bool PackedEncoding::Encode() {
    if (this->isEncoded)
        return true;
    auto mod = this->encodingParams->GetPlaintextModulus();

    if ((this->typeFlag == IsNativePoly) || (this->typeFlag == IsDCRTPoly)) {
        size_t i;

        NativeVector tempVector = NativeVector(this->GetElementRingDimension(), mod);

        NativeInteger originalSF = scalingFactorInt;
        for (size_t j = 1; j < noiseScaleDeg; j++) {
            scalingFactorInt = scalingFactorInt.ModMul(originalSF, mod);
        }

        for (i = 0; i < value.size(); i++) {
            if ((PlaintextModulus)llabs(value[i]) >= mod) {
                OPENFHE_THROW("Cannot encode integer " + std::to_string(value[i]) + " at position " +
                              std::to_string(i) + " that is > plaintext modulus " + std::to_string(mod));
            }

            if (value[i] < 0) {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                tempVector[i] = NativeInteger(mod) - NativeInteger((uint64_t)llabs(value[i]));
            }
            else {
                tempVector[i] = NativeInteger(value[i]);
            }
        }

        // no need to do extra multiplications for many scenarios when the scaling factor is 1, e.g., in BFV
        if (scalingFactorInt != 1) {
            tempVector.ModMulEq(scalingFactorInt);
        }

        if (this->typeFlag == IsNativePoly) {
            PlaintextModulus q = this->GetElementModulus().ConvertToInt();
            if (q < mod) {
                OPENFHE_THROW(
                    "the plaintext modulus size is larger than the size of "
                    "NativePoly modulus; increase the NativePoly modulus.");
            }

            // Calls the inverse NTT mod plaintext modulus
            this->PackNativeVector(this->encodingParams->GetPlaintextModulus(),
                                   this->encodedNativeVector.GetCyclotomicOrder(), &tempVector);
            tempVector.SetModulus(q);
            this->encodedNativeVector.SetValues(std::move(tempVector), Format::COEFFICIENT);
        }
        else {
            PlaintextModulus q = this->encodedVectorDCRT.GetParams()->GetParams()[0]->GetModulus().ConvertToInt();
            if (q < mod) {
                OPENFHE_THROW(
                    "the plaintext modulus size is larger than the size of "
                    "CRT moduli; either decrease the plaintext modulus or "
                    "increase the CRT moduli.");
            }

            // Calls the inverse NTT mod plaintext modulus
            this->PackNativeVector(this->encodingParams->GetPlaintextModulus(),
                                   this->encodedVectorDCRT.GetCyclotomicOrder(), &tempVector);
            // Switches from plaintext modulus to the modulus of the first RNS limb
            tempVector.SetModulus(q);
            NativePoly firstElement = this->GetElement<DCRTPoly>().GetElementAtIndex(0);
            firstElement.SetValues(std::move(tempVector), Format::COEFFICIENT);

            const std::shared_ptr<ILDCRTParams<BigInteger>> params           = this->encodedVectorDCRT.GetParams();
            const std::vector<std::shared_ptr<ILNativeParams>>& nativeParams = params->GetParams();

            // Sets the values for all other RNS limbs
            for (size_t ii = 1; ii < nativeParams.size(); ii++) {
                NativePoly tempPoly(firstElement);

                tempPoly.SwitchModulus(nativeParams[ii]->GetModulus(), nativeParams[ii]->GetRootOfUnity(),
                                       nativeParams[ii]->GetBigModulus(), nativeParams[ii]->GetBigRootOfUnity());

                this->encodedVectorDCRT.SetElementAtIndex(ii, std::move(tempPoly));
            }
            // Setting the first limb at the end make sure firstElement is available during the main loop
            this->encodedVectorDCRT.SetElementAtIndex(0, std::move(firstElement));
            this->encodedVectorDCRT.SetFormat(Format::EVALUATION);
        }
        this->isEncoded = true;
    }
    else {
        BigVector temp(this->GetElementRingDimension(), BigInteger(this->GetElementModulus()));

        BigInteger q = this->GetElementModulus();

        size_t i;
        for (i = 0; i < value.size(); i++) {
            BigInteger entry;

            if ((PlaintextModulus)llabs(value[i]) >= mod)
                OPENFHE_THROW("Cannot encode integer " + std::to_string(value[i]) + " at position " +
                              std::to_string(i) + " that is > plaintext modulus " + std::to_string(mod));

            if (value[i] < 0) {
                // It is more efficient to encode negative numbers using the ciphertext
                // modulus no noise growth occurs
                entry = BigInteger(mod) - BigInteger((uint64_t)llabs(value[i]));
            }
            else {
                entry = BigInteger(value[i]);
            }

            temp[i] = entry;
        }

        for (; i < this->GetElementRingDimension(); i++)
            temp[i] = BigInteger(0);

        // the input plaintext data is in the evaluation format
        this->GetElement<Poly>().SetValues(std::move(temp), Format::EVALUATION);

        // ilVector coefficients are packed and resulting ilVector is in COEFFICIENT
        // form.
        this->Pack(&this->GetElement<Poly>(), this->encodingParams->GetPlaintextModulus());

        this->isEncoded = true;
    }

    return true;
}

template <typename T>
static void fillVec(const T& poly, const PlaintextModulus& mod, std::vector<int64_t>& vec) {
    vec.clear();
    vec.reserve(poly.GetLength());

    int64_t half = int64_t(mod) / 2;
    // const typename T::Integer &q = poly.GetModulus();
    // typename T::Integer qHalf = q>>1;

    for (size_t i = 0; i < poly.GetLength(); i++) {
        int64_t val = poly[i].ConvertToInt();
        /*if (poly[i] > qHalf)
            val = (-(q-poly[i]).ConvertToInt());
    else
            val = poly[i].ConvertToInt();*/
        if (val > half)
            val -= mod;
        vec.push_back(val);
    }
}

bool PackedEncoding::Decode() {
    auto ptm = this->encodingParams->GetPlaintextModulus();

    if ((this->typeFlag == IsNativePoly) || (this->typeFlag == IsDCRTPoly)) {
        NativeInteger scfInv = scalingFactorInt.ModInverse(ptm);
        if (this->typeFlag == IsNativePoly) {
            this->Unpack(&this->GetElement<NativePoly>(), ptm);
            NativePoly firstElement = encodedNativeVector;
            firstElement            = firstElement.Times(scfInv);
            firstElement            = firstElement.Mod(ptm);
            fillVec(firstElement, ptm, this->value);
        }
        else {
            NativePoly firstElement = this->GetElement<DCRTPoly>().GetElementAtIndex(0);
            this->Unpack(&firstElement, ptm);
            firstElement = firstElement.Times(scfInv);
            firstElement = firstElement.Mod(ptm);
            fillVec(firstElement, ptm, this->value);
        }
    }
    else {
        this->Unpack(&this->GetElement<Poly>(), ptm);
        fillVec(this->encodedVector, ptm, this->value);
    }

    return true;
}

void PackedEncoding::Destroy() {
    m_initRoot.clear();
    m_bigModulus.clear();
    m_bigRoot.clear();

    m_automorphismGenerator.clear();
    m_toCRTPerm.clear();
    m_fromCRTPerm.clear();
}

void PackedEncoding::SetParams(usint m, EncodingParams params) {
    NativeInteger modulusNI(params->GetPlaintextModulus());  // native int modulus
    std::string exception_message;
    bool hadEx = false;

    // initialize the CRT coefficients if not initialized
    try {
        if (IsPowerOfTwo(m)) {
#pragma omp critical
            { SetParams_2n(m, params); }
        }
        else {
#pragma omp critical
            {
                const ModulusM modulusM = {modulusNI, m};
                // Arbitrary: Bluestein based CRT Arb. So we need the 2mth root of unity
                if (params->GetPlaintextRootOfUnity() == 0) {
                    NativeInteger initRoot = RootOfUnity<NativeInteger>(2 * m, modulusNI);
                    m_initRoot[modulusM]   = initRoot;
                    params->SetPlaintextRootOfUnity(m_initRoot[modulusM].ConvertToInt());
                }
                else {
                    m_initRoot[modulusM] = params->GetPlaintextRootOfUnity();
                }

                // Find a compatible big-modulus and root of unity for CRTArb
                if (params->GetPlaintextBigModulus() == 0) {
                    usint nttDim = pow(2, ceil(log2(2 * m - 1)));
                    if ((modulusNI.ConvertToInt() - 1) % nttDim == 0) {
                        m_bigModulus[modulusM] = modulusNI;
                    }
                    else {
                        usint bigModulusSize   = ceil(log2(2 * m - 1)) + 2 * modulusNI.GetMSB() + 1;
                        m_bigModulus[modulusM] = LastPrime<NativeInteger>(bigModulusSize, nttDim);
                    }
                    m_bigRoot[modulusM] = RootOfUnity<NativeInteger>(nttDim, m_bigModulus[modulusM]);
                    params->SetPlaintextBigModulus(m_bigModulus[modulusM]);
                    params->SetPlaintextBigRootOfUnity(m_bigRoot[modulusM]);
                }
                else {
                    m_bigModulus[modulusM] = params->GetPlaintextBigModulus();
                    m_bigRoot[modulusM]    = params->GetPlaintextBigRootOfUnity();
                }

                // Find a generator for the automorphism group
                if (params->GetPlaintextGenerator() == 0) {
                    NativeInteger M(m);  // Hackish typecast
                    NativeInteger automorphismGenerator = FindGeneratorCyclic<NativeInteger>(M);
                    m_automorphismGenerator[m]          = automorphismGenerator.ConvertToInt();
                    params->SetPlaintextGenerator(m_automorphismGenerator[m]);
                }
                else {
                    m_automorphismGenerator[m] = params->GetPlaintextGenerator();
                }

                // Create the permutations that interchange the automorphism and crt
                // ordering
                usint phim = GetTotient(m);
                auto tList = GetTotientList(m);
                auto tIdx  = std::vector<usint>(m, -1);
                for (usint i = 0; i < phim; i++) {
                    tIdx[tList[i]] = i;
                }

                m_toCRTPerm[m]   = std::vector<usint>(phim);
                m_fromCRTPerm[m] = std::vector<usint>(phim);

                usint curr_index = 1;
                for (usint i = 0; i < phim; i++) {
                    m_toCRTPerm[m][tIdx[curr_index]] = i;
                    m_fromCRTPerm[m][i]              = tIdx[curr_index];

                    curr_index = curr_index * m_automorphismGenerator[m] % m;
                }
            }
        }
    }
    catch (std::exception& e) {
        exception_message = e.what();
        hadEx             = true;
    }

    if (hadEx)
        OPENFHE_THROW(exception_message);
}

template <typename P>
void PackedEncoding::Pack(P* ring, const PlaintextModulus& modulus) const {
    OPENFHE_DEBUG_FLAG(false);

    usint m = ring->GetCyclotomicOrder();  // cyclotomic order
    NativeInteger modulusNI(modulus);      // native int modulus

    const ModulusM modulusM = {modulusNI, m};

    // Do the precomputation if not initialized
    if (this->m_initRoot[modulusM].GetMSB() == 0) {
        SetParams(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    usint phim = ring->GetRingDimension();

    OPENFHE_DEBUG("Pack for order " << m << " phim " << phim << " modulus " << modulusNI);

    // copy values from ring to the vector
    NativeVector slotValues(phim, modulusNI);
    for (usint i = 0; i < phim; i++) {
        slotValues[i] = (*ring)[i].ConvertToInt();
    }

    OPENFHE_DEBUG(*ring);
    OPENFHE_DEBUG(slotValues);

    // Transform Eval to Coeff
    if (IsPowerOfTwo(m)) {
        if (m_toCRTPerm[m].size() > 0) {
            // Permute to CRT Order
            NativeVector permutedSlots(phim, modulusNI);

            for (usint i = 0; i < phim; i++) {
                permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
            }
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverse(
                permutedSlots, m_initRoot[modulusM], m, &slotValues);
        }
        else {
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverse(
                slotValues, m_initRoot[modulusM], m, &slotValues);
        }
    }
    else {  // Arbitrary cyclotomic
        // Permute to CRT Order
        NativeVector permutedSlots(phim, modulusNI);
        for (usint i = 0; i < phim; i++) {
            permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
        }

        OPENFHE_DEBUG("permutedSlots " << permutedSlots);
        OPENFHE_DEBUG("m_initRoot[modulusM] " << m_initRoot[modulusM]);
        OPENFHE_DEBUG("m_bigModulus[modulusM] " << m_bigModulus[modulusM]);
        OPENFHE_DEBUG("m_bigRoot[modulusM] " << m_bigRoot[modulusM]);

        slotValues = ChineseRemainderTransformArb<NativeVector>().InverseTransform(
            permutedSlots, m_initRoot[modulusM], m_bigModulus[modulusM], m_bigRoot[modulusM], m);
    }

    OPENFHE_DEBUG("slotvalues now " << slotValues);
    // copy values into the slotValuesRing
    typename P::Vector slotValuesRing(phim, ring->GetModulus());
    for (usint i = 0; i < phim; i++) {
        slotValuesRing[i] = typename P::Integer(slotValues[i].ConvertToInt());
    }

    ring->SetValues(std::move(slotValuesRing), Format::COEFFICIENT);

    OPENFHE_DEBUG(*ring);
}

void PackedEncoding::PackNativeVector(const PlaintextModulus& modulus, uint32_t m, NativeVector* values) const {
    NativeVector& slotValues = *values;
    NativeInteger modulusNI(modulus);  // native int modulus
    usint phim = slotValues.GetLength();

    const ModulusM modulusM = {modulusNI, m};

    // Do the precomputation if not initialized
    if (this->m_initRoot[modulusM].GetMSB() == 0) {
        SetParams(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    // Transform Eval to Coeff
    if (IsPowerOfTwo(m)) {
        if (m_toCRTPerm[m].size() > 0) {
            // Permute to CRT Order
            NativeVector permutedSlots(phim, modulusNI);

            for (usint i = 0; i < phim; i++) {
                permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
            }
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverse(
                permutedSlots, m_initRoot[modulusM], m, &slotValues);
        }
        else {
            ChineseRemainderTransformFTT<NativeVector>().InverseTransformFromBitReverse(
                slotValues, m_initRoot[modulusM], m, &slotValues);
        }
    }
    else {  // Arbitrary cyclotomic
        // Permute to CRT Order
        NativeVector permutedSlots(phim, modulusNI);
        for (usint i = 0; i < phim; i++) {
            permutedSlots[i] = slotValues[m_toCRTPerm[m][i]];
        }

        slotValues = ChineseRemainderTransformArb<NativeVector>().InverseTransform(
            permutedSlots, m_initRoot[modulusM], m_bigModulus[modulusM], m_bigRoot[modulusM], m);
    }
}

template <typename P>
void PackedEncoding::Unpack(P* ring, const PlaintextModulus& modulus) const {
    OPENFHE_DEBUG_FLAG(false);

    usint m = ring->GetCyclotomicOrder();  // cyclotomic order
    NativeInteger modulusNI(modulus);      // native int modulus

    const ModulusM modulusM = {modulusNI, m};

    // Do the precomputation if not initialized
    if (this->m_initRoot[modulusM].GetMSB() == 0) {
        SetParams(m, EncodingParams(std::make_shared<EncodingParamsImpl>(modulus)));
    }

    usint phim = ring->GetRingDimension();  // ring dimension

    OPENFHE_DEBUG("Unpack for order " << m << " phim " << phim << " modulus " << modulusNI);

    // copy aggregate plaintext values
    NativeVector packedVector(phim, modulusNI);
    for (usint i = 0; i < phim; i++) {
        packedVector[i] = NativeInteger((*ring)[i].ConvertToInt());
    }

    OPENFHE_DEBUG(packedVector);

    // Transform Coeff to Eval
    NativeVector permutedSlots(phim, modulusNI);
    if (IsPowerOfTwo(m)) {
        ChineseRemainderTransformFTT<NativeVector>().ForwardTransformToBitReverse(packedVector, m_initRoot[modulusM], m,
                                                                                  &permutedSlots);
    }
    else {  // Arbitrary cyclotomic
        permutedSlots = ChineseRemainderTransformArb<NativeVector>().ForwardTransform(
            packedVector, m_initRoot[modulusM], m_bigModulus[modulusM], m_bigRoot[modulusM], m);
    }

    if (m_fromCRTPerm[m].size() > 0) {
        // Permute to automorphism Order
        for (usint i = 0; i < phim; i++) {
            packedVector[i] = permutedSlots[m_fromCRTPerm[m][i]];
        }
    }
    else {
        packedVector = permutedSlots;
    }

    OPENFHE_DEBUG(packedVector);

    // copy values into the slotValuesRing
    typename P::Vector packedVectorRing(phim, ring->GetModulus());
    for (usint i = 0; i < phim; i++) {
        packedVectorRing[i] = typename P::Integer(packedVector[i].ConvertToInt());
    }

    ring->SetValues(std::move(packedVectorRing), Format::COEFFICIENT);
}

void PackedEncoding::SetParams_2n(usint m, const NativeInteger& modulusNI) {
    if (!MillerRabinPrimalityTest(modulusNI)) {
        OPENFHE_THROW("The modulus value is [" + modulusNI.ToString() + "]. It must be prime.");
    }

    const ModulusM modulusM = {modulusNI, m};

    // Power of two: m/2-point FTT. So we need the mth root of unity
    m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);

    // Create the permutations that interchange the automorphism and crt ordering
    // First we create the cyclic group generated by 5 and then adjoin the
    // co-factor by multiplying by (-1)

    usint phim      = (m >> 1);
    usint phim_by_2 = (m >> 2);

    m_toCRTPerm[m]   = std::vector<usint>(phim);
    m_fromCRTPerm[m] = std::vector<usint>(phim);

    usint curr_index = 1;
    usint logn       = std::round(log2(m / 2));
    for (usint i = 0; i < phim_by_2; i++) {
        m_toCRTPerm[m][ReverseBits((curr_index - 1) / 2, logn)] = i;
        m_fromCRTPerm[m][i]                                     = ReverseBits((curr_index - 1) / 2, logn);

        usint cofactor_index = curr_index * (m - 1) % m;

        m_toCRTPerm[m][ReverseBits((cofactor_index - 1) / 2, logn)] = i + phim_by_2;
        m_fromCRTPerm[m][i + phim_by_2]                             = ReverseBits((cofactor_index - 1) / 2, logn);

        curr_index = curr_index * 5 % m;
    }
}

void PackedEncoding::SetParams_2n(usint m, EncodingParams params) {
    NativeInteger modulusNI(params->GetPlaintextModulus());  // native int modulus

    if (!MillerRabinPrimalityTest(modulusNI)) {
        OPENFHE_THROW("The modulus value is [" + modulusNI.ToString() + "]. It must be prime.");
    }

    const ModulusM modulusM = {modulusNI, m};

    // Power of two: m/2-point FTT. So we need the mth root of unity
    if (params->GetPlaintextRootOfUnity() == 0) {
        m_initRoot[modulusM] = RootOfUnity<NativeInteger>(m, modulusNI);
        params->SetPlaintextRootOfUnity(m_initRoot[modulusM]);
    }
    else {
        m_initRoot[modulusM] = params->GetPlaintextRootOfUnity();
    }

    // Create the permutations that interchange the automorphism and crt ordering
    // First we create the cyclic group generated by 5 and then adjoin the
    // co-factor by multiplying by (-1)
    usint phim      = (m >> 1);
    usint phim_by_2 = (m >> 2);

    m_toCRTPerm[m]   = std::vector<usint>(phim);
    m_fromCRTPerm[m] = std::vector<usint>(phim);

    usint curr_index = 1;
    usint logn       = std::round(log2(m >> 1));
    for (usint i = 0; i < phim_by_2; i++) {
        m_toCRTPerm[m][ReverseBits((curr_index - 1) / 2, logn)] = i;
        m_fromCRTPerm[m][i]                                     = ReverseBits((curr_index - 1) / 2, logn);

        usint cofactor_index = curr_index * (m - 1) % m;

        m_toCRTPerm[m][ReverseBits((cofactor_index - 1) / 2, logn)] = i + phim_by_2;
        m_fromCRTPerm[m][i + phim_by_2]                             = ReverseBits((cofactor_index - 1) / 2, logn);

        curr_index = curr_index * 5 % m;
    }
}
}  // namespace lbcrypto
