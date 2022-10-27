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

#define PROFILE

#include "math/dftransform.h"

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "openfhe.h"


namespace lbcrypto {

uint32_t findOPTratio(double slots){
	if(slots < 128)
		return 0;
	
	auto temp = ceil(sqrt(slots/12.));
	return ceil(slots/temp);
}

template <typename Element>
std::vector<std::vector<std::complex<double>>> CryptoContextImpl<Element>::EvalLTPrecomputeNew(const std::vector<std::vector<std::complex<double>>>& A, const std::vector<std::vector<std::complex<double>>>& B,
    uint32_t dim1, uint32_t orientation, double scale, uint32_t L) {
  uint32_t slots = A.size();
  uint32_t m = this->GetCyclotomicOrder();

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  int gStep = ceil(static_cast<double>(slots) / bStep);

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParamsCKKS =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(m, moduli, roots);
  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);
  std::vector<ConstPlaintext> result(slots);
  std::vector<std::vector<std::complex<double>>> vecs(slots);
  if (0) {  // vertical concatenation - used during homomorphic encoding
  // This part is not changed so should never be touched or it will cause memory leakage
    // #pragma omp parallel for
	  for (int j = 0; j < gStep; j++) {
		  int offset = -bStep * j;
		  for (int i = 0; i < bStep; i++) {
			  if (bStep * j + i < static_cast<int>(slots)) {
				  auto vecA = ExtractShiftedDiagonal(A, bStep * j + i);
				  auto vecB = ExtractShiftedDiagonal(B, bStep * j + i);

				  vecA.insert(vecA.end(), vecB.begin(), vecB.end());
				  for (uint32_t k = 0; k < vecA.size(); k++) vecA[k] *= scale;

				  result[bStep * j + i] =
					  this->MakeCKKSPackedPlaintext(Rotate(Fill(vecA, m / 4), offset), 1, towersToDrop, elementParamsPtr2);
			  }
		  }
	  }
  } else {  // horizontal concatenation - used during homomorphic decoding
    std::vector<std::vector<std::complex<double>>> newA(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
      auto vecA = A[i];
      auto vecB = B[i];
      vecA.insert(vecA.end(), vecB.begin(), vecB.end());
      newA[i] = vecA;
    }


#pragma omp parallel for
    for (int j = 0; j < gStep; j++) {
        // int offset = -bStep*j;
        for (int i = 0; i < bStep; i++) {
        if (bStep*j + i < static_cast<int>(slots)) {
          // shifted diagonal is computed for rectangular map newA of dimension
          // slots x 2*slots
          auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
          for (uint32_t k = 0; k < vec.size(); k++) vec[k] *= scale;
		  vecs[bStep * j + i] = Fill(vec, m / 4);

        //   result[bStep * j + i] =
            //   cc.MakeCKKSPackedPlaintext(Rotate(Fill(vec, m / 4), offset), 1, towersToDrop, elementParamsPtr2);
        }
      }
    }
  }

  return vecs;
}

template <typename Element>
std::vector<std::vector<std::complex<double>>> CryptoContextImpl<Element>::EvalLTPrecomputeRectNew(const std::vector<std::vector<std::complex<double>>>& A, uint32_t dim1, double scale, uint32_t L) const {
  if ((A.size()/A[0].size())*A[0].size() != A.size()) {
    OPENFHE_THROW(math_error, "The matrix passed to EvalLTPrecompute is not in proper rectangle shape");
  }

  uint32_t slots = A[0].size();
  uint32_t m = this->GetCyclotomicOrder();

  // Computing the baby-step g and the giant-step h.
  int g, h;
  if (dim1 == 0)
    g = ceil(sqrt(slots));
  else
    g = dim1;

  h = ceil(static_cast<double>(slots) / g);

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParamsCKKS =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr =
      std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(m, moduli, roots);
  auto elementParamsPtr2 =
      std::dynamic_pointer_cast<typename Element::Params>(elementParamsPtr);

  auto num_slices = A.size()/A[0].size();
  std::vector<std::vector<std::vector<std::complex<double>>>> A_slices(num_slices);
  for(size_t i = 0; i < num_slices; i++){
    A_slices[i] = std::vector<std::vector<std::complex<double>>>(A.begin()+i*A[0].size(), A.begin()+(i+1)*A[0].size());
  }
	std::vector<std::vector<std::complex<double>>> diags(slots);
// #pragma omp parallel for
  for (int j = 0; j < h; j++) {
    for (int i = 0; i < g; i++) {
      if (g * j + i < static_cast<int>(slots)) {

        std::vector<std::complex<double>> diag(0);
        for(uint32_t k = 0; k < A.size()/A[0].size(); k++){
          auto tmp = ExtractShiftedDiagonal(A_slices[k], g * j + i);
          diag.insert(diag.end(), tmp.begin(), tmp.end());
        }
        for (uint32_t k = 0; k < diag.size(); k++) diag[k] *= scale;
		diags[g * j + i] = diag;
      }
    }
  }

  return diags;
}

//#pragma clang diagnostic push
//#pragma ide diagnostic ignored "openmp-use-default-none"
template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLTWithPrecompNew(                                                    const std::vector<std::vector<std::complex<double>>>& A,
                                                                     ConstCiphertext<Element> ct, uint32_t dim1, uint32_t L) {

    uint32_t slots = A.size();

    // Computing the baby-step g and the giant-step h.
    uint32_t g = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
    uint32_t h = ceil(static_cast<double>(slots) / g);

    uint32_t m = this->GetCyclotomicOrder();
    uint32_t n = this->GetRingDimension();

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used
    // later on)
    auto digits = this->EvalFastRotationPrecompute(ct);

    std::vector<Ciphertext<Element>> fastRotation(g - 1);
	// make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParamsCKKS =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(this->GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParamsCKKS->GetElementParams());
  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }
  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParamsCKKS->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr =
      std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(m, moduli, roots);
  auto elementParamsPtr2 =
      std::dynamic_pointer_cast<typename Element::Params>(elementParamsPtr);

    // hoisted automorphisms
#pragma omp parallel for
for (uint32_t j = 1; j < g; j++) {
    fastRotation[j - 1] = this->EvalFastRotationExt(ct, j, digits, true);
}
Ciphertext<Element> result;
Element first;

for (uint32_t j = 0; j < h; j++) {
	int offset = (j == 0) ? 0 : -g * int(j);
	auto temp = this->MakeCKKSPackedPlaintext(Rotate(Fill(A[g * j], m / 4), offset), 1, towersToDrop, elementParamsPtr2);
    Ciphertext<Element> inner = this->EvalMult(KeySwitchExt(ct, true), temp);
    for (uint32_t i = 1; i < g; i++) {
        if (g * j + i < slots) {
			auto tempi = this->MakeCKKSPackedPlaintext(Rotate(Fill(A[g * j + i], m / 4), offset), 1, towersToDrop, elementParamsPtr2);
            inner = this->EvalAdd(inner, this->EvalMult(tempi, fastRotation[i - 1]));
        }
    }

    if (j == 0) {
        first = KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        result = inner;
    } else {
        inner = KeySwitchDown(inner);
        // Find the automorphism index that corresponds to rotation index index.
        usint autoIndex = FindAutomorphismIndex2nComplex(g * j, m);
        std::vector<usint> map(n);
        PrecomputeAutoMap(n, autoIndex, &map);
        Element firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
        first += firstCurrent;

        auto innerDigits = this->EvalFastRotationPrecompute(inner);
        result = this->EvalAdd(result, EvalFastRotationExt(inner, g * j, innerDigits, false));
    }
}

result = KeySwitchDown(result);
auto elements = result->GetElements();
elements[0] += first;
result->SetElements(elements);

return result;
}

template <typename Element>
Ciphertext<Element> CryptoContextImpl<Element>::EvalLTRectNew(                                            const std::vector<std::vector<std::complex<double>>>& A,
                                                          ConstCiphertext<Element> ct, uint32_t dim1, double scale, uint32_t L) {

  std::vector<std::vector<std::complex<double>>> Acopy(A);
  if((A.size() % A[0].size()) != 0){
    std::vector<std::vector<std::complex<double>>> padding(A[0].size() - (A.size() % A[0].size()));
    for(size_t i = 0; i < padding.size(); i++){
      padding[i] = std::vector<std::complex<double>>(A[0].size());
    }
    Acopy.insert(Acopy.end(), padding.begin(), padding.end());
  }

	
  auto precomputedA = EvalLTPrecomputeRectNew(Acopy, dim1, scale, L);
  auto res = EvalLTWithPrecompNew(precomputedA, ct, dim1, L);
  precomputedA.clear();

  return res;
}

///////////////////////////////////////// Auxiliary Funcitons

Ciphertext<DCRTPoly> slotsToCoeffs(const Ciphertext<DCRTPoly>& ciphertext1, CryptoContextImpl<DCRTPoly>& cc, uint64_t slots, uint32_t dim1){ // TODO: dim1 configurable
	uint32_t msub = 4 * slots;

	auto ciphertext2 = cc.getPaddingCT();
	ciphertext2->SetElements(ciphertext1->GetElements());
	auto input = cc.Compress(ciphertext2, 2);

	// computes indices for all primitive roots of unity
	std::vector<uint32_t> rotGroup(slots);
	uint32_t fivePows = 1;
	for (uint32_t i = 0; i < slots; ++i) {
		rotGroup[i] = fivePows;
		fivePows *= 5;
		fivePows %= msub;
	}
	// computes all powers of a primitive root of unity exp(2*M_PI/m)
	std::vector<std::complex<double>> ksiPows(cc.GetRingDimension()*2 + 1);
	for (uint32_t j = 0; j < msub; ++j) {
		double angle = 2.0 * M_PI * j / msub;
		ksiPows[j].real(cos(angle));
		ksiPows[j].imag(sin(angle));
	}
	ksiPows[msub] = ksiPows[0];

	std::vector<std::vector<std::complex<double>>> U0(slots), U1(slots), U0hatT(
			slots), U1hatT(slots);
	// allocate all vectors
	for (size_t i = 0; i < slots; i++) {
		U0[i] = std::vector<std::complex<double>>(slots);
		U1[i] = std::vector<std::complex<double>>(slots);
	}

	for (size_t i = 0; i < slots; i++) {
		for (size_t j = 0; j < slots; j++) {
			U0[i][j] = ksiPows[(j * rotGroup[i]) % msub];
			U1[i][j] = std::complex<double>( { 0, 1 }) * U0[i][j];
		}
	}
	auto U0Pre = cc.EvalLTPrecomputeNew(U0, U1, dim1, 1, 1, 1);
	auto ctxtDec0 = cc.EvalLTWithPrecompNew(U0Pre, input, dim1, 1);
	auto ctxtDec = cc.EvalAdd(ctxtDec0, cc.EvalAtIndex(ctxtDec0, slots));
	return ctxtDec;
}

std::vector<std::vector<NativeInteger>> ExtractLWEpacked(const Ciphertext<DCRTPoly>& ct){
	auto N = ct->GetElements()[0].GetLength();
	// cout << ct->GetElements().size() << "xxxxxxxxx" << endl;
	auto A = ct->GetElements()[1];
	auto B = ct->GetElements()[0];
	auto originalA = A.GetElementAtIndex(0);
	auto originalB = B.GetElementAtIndex(0);
	originalA.SetFormat(Format::COEFFICIENT);
	originalB.SetFormat(Format::COEFFICIENT);

	std::vector<std::vector<NativeInteger>> res(2);
	// res[0] = std::vector<NativeInteger>(N);
	// res[1] = std::vector<NativeInteger>(N);

	for(uint32_t i = 0; i < N; i++){
		res[1].push_back(originalA[i]);
		res[0].push_back(originalB[i]);
		// res[1][i] = originalA[i];
		// res[0][i] = originalB[i];
		// if(i < 10)
			// cout << originalA[i] << " " << originalB[i] << " " << N << endl;
	}
	return res;
}

std::shared_ptr<LWECiphertextImpl> ExtractLWECiphertext(const std::vector<std::vector<NativeInteger>>& aANDb, 
														NativeInteger modulus, BinFHEContext& m_ccLWE, uint32_t index = 0){ 

    uint32_t n = m_ccLWE.GetParams()->GetLWEParams()->Getn();
	auto N = aANDb[0].size();
	NativeVector a(n, modulus);
	NativeInteger b;
	for(uint32_t i = 0; i < n; i += 1){
		if(i <= index){
			a[i] = modulus - aANDb[1][index-i];
		} else {
			a[i] = aANDb[1][N + index - i];
		}
	}
	b = aANDb[0][index];
	auto res =
        std::make_shared<LWECiphertextImpl>(std::move(a), std::move(b));
	return res;
}

// template <typename Element>
EvalKey<DCRTPoly> switchingKeyGenRLWE(PrivateKey<DCRTPoly>&  RLWElwesk, 
					const PrivateKey<DCRTPoly>& ckksSK, 
					const std::shared_ptr<LWEPrivateKeyImpl>& LWEsk, 
					CryptoContextImpl<DCRTPoly>& ccCKKS){
	// Extract CKKS params
	auto skelements = ckksSK->GetPrivateElement();
	skelements.SetFormat(Format::COEFFICIENT);
	auto lweskElements = LWEsk->GetElement();
	for(size_t i = 0; i < skelements.GetNumOfElements(); i++){
		auto skelementsPlain = skelements.GetElementAtIndex(i);
		for(size_t j = 0; j < skelementsPlain.GetLength(); j++){
			if(j >= lweskElements.GetLength()){
				skelementsPlain[j] = 0;
			} else {
				if(lweskElements[j] == 0){
					skelementsPlain[j] = 0;
				}
				else if(lweskElements[j].ConvertToInt() == 1){
					skelementsPlain[j] = 1;
				}
				else
					skelementsPlain[j] = skelementsPlain.GetModulus()-1;
			}
		}
		skelements.SetElementAtIndex(i, skelementsPlain);
	}
	skelements.SetFormat(Format::EVALUATION);
	// cout << "2" << endl;
	RLWElwesk->SetPrivateElement(std::move(skelements));
	// cout << "2.1" << endl;
	
	return ccCKKS.KeySwitchGen(ckksSK, RLWElwesk);;
}

NativeInteger RoundqQAlter(const NativeInteger &v, const NativeInteger &q,
                      const NativeInteger &Q) {
  return NativeInteger((uint64_t)std::floor(0.5 + v.ConvertToDouble() *
                                                      q.ConvertToDouble() /
                                                      Q.ConvertToDouble()))
      .Mod(q);
}

// Assumes the left number of levels would be consumed by slots to coeffs
// Right now only linear transformation for S2C
std::vector<std::shared_ptr<LWECiphertextImpl>> CKKStoFHEW(const Ciphertext<DCRTPoly>& ct, 
				const EvalKey<DCRTPoly>& swk,
				// const std::pair<std::shared_ptr<LWECryptoParams>, std::shared_ptr<LWESwitchingKey>>& pair_lwe, 
				const uint32_t& num_slots /* assume no non-contiguous slots for prototype */,
				//const LPPrivateKey<DCRTPoly>& ckksSK, const std::shared_ptr<LWEPrivateKeyImpl>& LWEsk,
				CryptoContextImpl<DCRTPoly>& ccCKKS,
				BinFHEContext& m_ccLWE,
				const uint64_t& m_modulus_to, 
				uint32_t dim1
				){
	uint32_t n = m_ccLWE.GetParams()->GetLWEParams()->Getn();
	std::vector<std::shared_ptr<LWECiphertextImpl>> LWEciphertexts;

	// Step 1. Slots to coeffs Checked
	// TIC(t);
	// cout << ct->GetLevel() << " " << ct->GetDepth() << endl;
#if defined(BRIDGING_DEBUG)
  TimeVar t;
  TIC(t);
#endif
	auto ctCoeffs = slotsToCoeffs(ct, ccCKKS, ccCKKS.GetbridgingUpperbound(), dim1);
#if defined(BRIDGING_DEBUG)
  cout << "slotsToCoeffs time: " << TOC_MS(t) << " ms" << endl;
  TIC(t);
#endif
	// cout << ct->GetLevel() << " " << ct->GetDepth() << endl;
	auto ctCoeffs2 = ccCKKS.Compress(ctCoeffs);
	auto ctCoeffs3 = ccCKKS.KeySwitch(ctCoeffs2, swk);
	// cout << "SlotsToCoeffs and KeySwitching time:" << "\t" << TOC_US(t) << "us" << endl;
	auto modulus_from = ctCoeffs3->GetElements()[0].GetModulus();
	
	// Step 2. Extraction Check
	// TIC(t);
	auto AandB = ExtractLWEpacked(ctCoeffs3);
	uint32_t counter = 0;
	for(uint32_t i = 0; i < ccCKKS.GetRingDimension()/2; i+=(ccCKKS.GetRingDimension()/2/ccCKKS.GetbridgingUpperbound())){
		// cout << i << endl;
		auto temp = ExtractLWECiphertext(AandB, modulus_from, m_ccLWE, i);
		LWEciphertexts.push_back(temp);
		counter++;
		if(counter == num_slots)
			break;
	}

	if(m_modulus_to != modulus_from){
		for(uint32_t i = 0; i < num_slots; i++){
				auto original_a = LWEciphertexts[i]->GetA();
				auto original_b = LWEciphertexts[i]->GetB();
				// round Q to 2betaQ/q
				NativeVector a_round(n, m_modulus_to);
				for (uint32_t j = 0; j < n; ++j) a_round[j] = RoundqQAlter(original_a[j], m_modulus_to, modulus_from);
				NativeInteger b_round = RoundqQAlter(original_b, m_modulus_to, modulus_from);
				LWEciphertexts[i] = std::make_shared<LWECiphertextImpl>(std::move(a_round), std::move(b_round));
			}
	} 
	
#if defined(BRIDGING_DEBUG)
  cout << "The rest of CKKStoFHEW time: " << TOC_MS(t) << " ms" << endl;
  TIC(t);
#endif
	// cout << "Modulus Switching time:" << "\t" << TOC_US(t) << "us, for " << num_slots << " ciphertexts." << endl;

	return LWEciphertexts;
}

#define Pi 3.14159265358979323846

const std::vector<double> g_coefficientsFHEW({0.12374520595985596,-0.024493557018250355,0.12864468848664823,-0.022457247544100528,0.14212115805701445,-0.017957992051578768,0.16008197693836673,-0.010356206464121682,0.17458294827703502,0.00069764786235339998,0.17332698445029668,0.014415562869726376,0.14160775388871905,0.027864569474609573,0.069148468982727820,0.035526399816634920,-0.037447507468382400,0.030784364050481634,-0.14213082120974599,0.010536337716667865,-0.18217520706655785,-0.018300072435107985,-0.10530280399220575,-0.036635225634281232,0.063245761563600247,-0.024621862783145716,0.18637445454314894,0.013729575864447110,0.11222307428645424,0.038598793311852696,-0.11168516754739241,0.012080920618371495,-0.18659866591874685,-0.035177634491084547,0.045610268782696452,-0.022904274431946273,0.20596542789491695,0.035779596840663418,-0.058845266934630935,0.018081887408798798,-0.19990619011732119,-0.045204187386174363,0.17082649558144314,0.011579873620065162,0.071223906127701769,0.036382655327408961,-0.25627153589792723,-0.056917019465110817,0.27883266642409893,0.049010015444059682,-0.20154109032448050,-0.030744546614836471,0.11210264912446273,0.015391581650897743,-0.051073798502557596,-0.0064364133239901561,0.019737893020776255,0.0023116263569468824,-0.0066187956931535409,-0.00072666134496683578,0.0019571579355719178,0.00020273091214757335,-0.00051654852604892537,-0.000050738024382956559,0.00012285121546532282,0.000011489333007212300,-0.000026533625113716339,-2.3706421200493703e-6,5.2379797865091124e-6,4.4835516327328205e-7,-9.5029543387417991e-7,-7.8120874338737986e-8,1.5919559834171849e-7,1.2595457343778094e-8,-2.4727027247235347e-8,-1.8864428620949427e-9,3.5740686615015240e-9,2.6335875926982934e-10,-4.8229587614520840e-10,-3.4376425551345850e-11,6.0938385423901051e-11,4.2073635461995284e-12,-7.2286895570496097e-12,-4.8383394669004246e-13,8.0675042177267387e-13,5.2627066250433825e-14,-8.5374903152073829e-14,-5.2108754265341964e-15,9.0589209043009958e-15} );

Ciphertext<DCRTPoly> FHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWEciphertexts, const Ciphertext<DCRTPoly>& EncLWEsk, 
									CryptoContextImpl<DCRTPoly>& cc, 
									uint32_t n, int dim2,
									uint64_t q, double pmin, double pmax,
                                    usint init_size){
	if(!LWEciphertexts.size()){
		OPENFHE_THROW(type_error, "Empty input FHEW ciphertext vector");
	}

    auto N = LWEciphertexts.size();
    int K = 64;

#if defined(BRIDGING_DEBUG)
  TimeVar t;
  TIC(t);
#endif

    std::vector<std::vector<std::complex<double>>> A(N, std::vector<std::complex<double>>(n, 0));
    std::vector<std::complex<double>> b(N, 1./4.);
    Plaintext BPlain;
    for(uint32_t i = 0; i < N; i++){
        auto a = LWEciphertexts[i]->GetA();
        for(uint32_t j = 0; j < a.GetLength(); j++){
            A[i][j] = std::complex<double>(a[j].ConvertToDouble()/double(q), 0);
        }
        b[i] = std::complex<double>(LWEciphertexts[i]->GetB().ConvertToDouble()/double(q), 0);
    }
	LWEciphertexts.clear();

    // Second step: homomorphically compute b - <a,s>
	Ciphertext<DCRTPoly> AdotS;
	const auto cryptoParams =
			    std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(EncLWEsk->GetCryptoParameters());
	AdotS = cc.EvalLTRectNew(A, EncLWEsk, dim2, 1, init_size);
	auto AdotS1 = cc.Compress(AdotS, init_size - AdotS->GetLevel()-1);

	// cout << "?" << endl;
    BPlain = cc.MakeCKKSPackedPlaintext(b);
    auto BminusAdotS = cc.EvalAdd(cc.EvalNegate(AdotS1), BPlain); 

#if defined(BRIDGING_DEBUG)
  cout << "<a,s>+b time: " << TOC_MS(t) << " ms" << endl;
  TIC(t);
#endif

    // Highly likely the result in within [-20000, 20000]
    // 1. for tenary secret with n =512, difference is highly within [-90,90]
    // 2. Each difference times with a number unifromly from Z_q = [0,512)
    // 3. We get Irwin–Hall distribution, so we get it should be within [-5*sqrt(90/12)*512 + 45*512, 5*sqrt(90/12)*512 + 45*512] \subset [-20000, 20000]
    // Can be tighter. This should give ~ 2^{-40} failure probability
    // Then we have q =512 as a cycle
    // Then it's roughly [-39, 39]. This is independent of q.
	auto BminusAdotS1 = cc.EvalMult(BminusAdotS, 1./K);  
	auto BminusAdotS2 = cc.Compress(BminusAdotS1, init_size - BminusAdotS1->GetLevel()-1);


	// Third step: homomorphically evaluate modular function. We do it by using sin approximation
	double b_cheby = -1;
    double a_cheby = -b_cheby;
    auto BminusAdotS3 = cc.EvalChebyshevSeries(BminusAdotS2,g_coefficientsFHEW,a_cheby,b_cheby);

    int32_t r = 3;
	for (int32_t j = 1; j < r + 1; j++) {
	    BminusAdotS3 = cc.EvalMult(BminusAdotS3, BminusAdotS3);
	    BminusAdotS3 = cc.EvalAdd(BminusAdotS3,BminusAdotS3);
	    double scalar = 1.0/std::pow((2.0*Pi),std::pow(2.0,j-r));
	    BminusAdotS3 = cc.EvalSub(BminusAdotS3,scalar);
	    BminusAdotS3 = cc.Compress(BminusAdotS3, init_size - BminusAdotS3->GetLevel()-1);
	}
	double pdomain = 2*Pi*(pmax - pmin)/2;
	std::vector<std::complex<double>> pdomainVec(cc.GetRingDimension()/2, 0);
	for(size_t i = 0; i < N; i++){
		pdomainVec[i] = std::complex<double>(pdomain, 0);
	}
	auto pdomainPlain = cc.MakeCKKSPackedPlaintext(pdomainVec);
	auto BminusAdotSres = cc.EvalMult(BminusAdotS3, pdomainPlain); 
    cc.RescaleInPlace(BminusAdotSres);
	if(pmin == 0){ // if only in the postive range, shift it correctly.
		std::vector<std::complex<double>> pdomainVec(cc.GetRingDimension()/2, 0);
		for(size_t i = 0; i < N; i++){
			pdomainVec[i] = std::complex<double>((pmax - pmin)/2, 0);
		}
		auto pdomainPlain = cc.MakeCKKSPackedPlaintext(pdomainVec);
		BminusAdotSres = cc.EvalAdd(BminusAdotSres, pdomainPlain); 
	}
#if defined(BRIDGING_DEBUG)
  cout << "Chebyshev time: " << TOC_MS(t) << " ms" << endl;
  TIC(t);
#endif	

    return BminusAdotSres;
}

///////////////////////////////////////// Auxiliary Funcitons Finish

template <>
std::pair<KeyPair<DCRTPoly>, LWEPrivateKey> 
CryptoContextImpl<DCRTPoly>::EvalBridgeSetup(bool dynamic, uint32_t logQ, SecurityLevel sl, uint32_t bridgingUpperbound, uint64_t init_size, uint64_t dcrtBits){
    m_init_size_inner = init_size; // Configurable
	m_dcrtBits = dcrtBits;
	m_bridgingUpperbound = bridgingUpperbound; 

    uint64_t ringDim = 1 << 16; // At least 1<<16 for 128 bit security for dcrtBits ~ 50 bit. 1<<15 is enough for 128 bit security for dcrtBits ~ 40 bit
	if(ringDim >= this->GetRingDimension()) { // TODO: now only supports 128 bit security, no 192/256 bit.
		m_innerCC = false;
		ringDim = this->GetRingDimension();
	} else {
		m_innerCC = false;
	}
	// m_innerCC = true;

    m_modulus_to = 1<<logQ;
    if(sl == HEStd_128_classic)
      m_ccLWE.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, dynamic);
    else
      m_ccLWE.GenerateBinFHEContext(TOY, false, logQ, 0, GINX, dynamic);

    std::pair<KeyPair<DCRTPoly>, LWEPrivateKey> res;
    res.second = m_ccLWE.KeyGen(m_modulus_to);

    return res;
}

std::vector<int32_t> FindLTRotationIndices(uint32_t dim1, uint32_t m,
					  uint32_t blockDimension) {

        uint32_t slots;

	if ((blockDimension == 0) || (blockDimension == m/4)) // fully-packed mode
	    slots = m/4;
	else //sparse mode
	    slots = blockDimension;

        // Computing the baby-step g and the giant-step h.
        int g = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
        int h =  ceil((double)slots/g);

        // computing all indices for baby-step giant-step procedure
        // ATTN: resize() is used as indexListEvalLT may be empty here
		std::vector<int32_t> indexListEvalLT;

        // indexListEvalLT.reserve(g + h - 2);
        for(int i = 0; i < g; i++)
            indexListEvalLT.emplace_back(i + 1);
        for(int i = 2; i < h; i++)
            indexListEvalLT.emplace_back(g*i);

        return indexListEvalLT;
}


template <>
// template <typename Element>
void CryptoContextImpl<DCRTPoly>::EvalBridgeKeyGen(const std::pair<KeyPair<DCRTPoly>, LWEPrivateKey>& keys,
                                                        const KeyPair<DCRTPoly>& thiskey){
	uint32_t dim1 = findOPTratio(double(m_bridgingUpperbound));
	uint32_t n  = m_ccLWE.GetParams()->GetLWEParams()->Getn(); // LWE's n
	uint32_t dim2 = findOPTratio(double(n));
	if(n != 512)
		dim2 = 0;
	auto temp = m_bridgingUpperbound;

	CCParams<CryptoContextCKKSRNS> parameters;
	parameters.SetSecurityLevel(HEStd_NotSet);
	parameters.SetRingDim(this->GetRingDimension());
	parameters.SetMultiplicativeDepth(10000+m_init_size_inner);
	parameters.SetScalingModSize(m_dcrtBits);
	parameters.SetScalingTechnique(FIXEDMANUAL);
	parameters.SetKeySwitchTechnique(HYBRID);
	parameters.SetFirstModSize(60);
	parameters.SetDigitSize(1);
	m_ccCKKSlower = GenCryptoContext(parameters);

	m_ccCKKSlower->Enable(PKE);
    m_ccCKKSlower->Enable(KEYSWITCH);
    m_ccCKKSlower->Enable(LEVELEDSHE);
    m_ccCKKSlower->Enable(ADVANCEDSHE);
    m_ccCKKSlower->Enable(FHE);
    // m_ccCKKSlower->Enable(PKE);m_ccCKKSlower->Enable(SHE);m_ccCKKSlower->Enable(LEVELEDSHE);m_ccCKKSlower->Enable(ADVANCEDSHE);m_ccCKKSlower->Enable(FHE);

	auto lowerkp = m_ccCKKSlower->KeyGen();
	std::vector<std::complex<double>> tempzerolower(m_ccCKKSlower->GetRingDimension()/2, 0);
	auto zerolower = m_ccCKKSlower->MakeCKKSPackedPlaintext(tempzerolower);
	m_ccCKKSlower->m_CTforPadding = m_ccCKKSlower->Encrypt(lowerkp.publicKey, zerolower);

	auto skelements2 = thiskey.secretKey->GetPrivateElement();
	auto skelements = lowerkp.secretKey->GetPrivateElement();
	skelements.SetFormat(Format::COEFFICIENT);
	for(size_t i = 0; i < skelements.GetNumOfElements(); i++){
		auto skelementsPlain = skelements2.GetElementAtIndex(i);
		skelementsPlain.SetFormat(Format::COEFFICIENT);
		skelements.SetElementAtIndex(i, skelementsPlain);
	}
	skelements.SetFormat(Format::EVALUATION);
	lowerkp.secretKey->SetPrivateElement(std::move(skelements));
	
	m_ccCKKSlower->SetbridgingUpperbound(temp);
	std::vector<int32_t> indexListEvalLT_lower = FindLTRotationIndices(dim1, m_ccCKKSlower->GetRingDimension()*2, m_bridgingUpperbound);
	m_ccCKKSlower->EvalAtIndexKeyGen(lowerkp.secretKey, indexListEvalLT_lower);
	m_ccCKKSlower->EvalAtIndexKeyGen(lowerkp.secretKey, {int(temp)});

    // this cc
    this->EvalMultKeyGen(thiskey.secretKey);
	std::vector<int> stepone;
	for(size_t i = 1; i <this->GetRingDimension()/2; i*=2){
			// cout << i << endl;
			stepone.push_back(int(i));
			if (i <= temp)
				stepone.push_back(-int(i));
		}
	this->EvalAtIndexKeyGen(thiskey.secretKey, stepone);

    m_ccLWE.BTKeyGen(keys.second, m_modulus_to); 

    std::vector<std::complex<double>> tempzero1(this->GetRingDimension()/2, 0);
    auto LWEskPlain1 = this->MakeCKKSPackedPlaintext(tempzero1);
	this->m_CTforPadding = this->Encrypt(thiskey.publicKey, LWEskPlain1);

    KeyPair<DCRTPoly> kpLWE2 = m_ccCKKSlower->KeyGen();
	m_CKKStoFHEWswkOutside = switchingKeyGenRLWE(kpLWE2.secretKey, lowerkp.secretKey, keys.second, *m_ccCKKSlower);

    // generate FHEW to CKKS swk
    auto skElmt = keys.second->GetElement();
    std::vector<std::complex<double>> LWEskDouble(n);
    for(uint32_t i = 0; i < n; i++) {auto tmp = skElmt[i].ConvertToDouble(); if(tmp == m_modulus_to-1) tmp = -1; LWEskDouble[i] = std::complex<double>(tmp, 0);}

    std::vector<std::complex<double>> input2(Fill(LWEskDouble,this->GetRingDimension()/2));
    Plaintext  LWEskPlainswk = this->MakeCKKSPackedPlaintext(input2);
	m_FHEWtoCKKSswkOutside = this->Encrypt(thiskey.publicKey, LWEskPlainswk);

	std::vector<int32_t> indexListEvalLT = FindLTRotationIndices(dim2, this->GetRingDimension()*2, n);
	this->EvalAtIndexKeyGen(thiskey.secretKey, indexListEvalLT);
	this->SetbridgingUpperbound(temp);
}

// Input: (1) a vector of CKKS ciphertexts, size w.
// (2) A number k: number of parallel argMax
// Together equivalent to a w*k matrix
// (3) switching key from CKKS to FHEW
// (4) switching key from FHEW to CKKS
// (5) CKKS CryptoContext
// (6) one smaller CKKS CryptoContext for efficiency, probably 2^16
// (7) BinFHEContext
// (8) Modulus of FHEW
// Goal: get one comparison
// Output: A vector of ciphertext, containing the results of comparison
// ***Assumption: (a) w*k < 2^16 / 2; (b) rotation to right by k is allowed; (c) input encrypting elements within [-0.25,0.25]
std::vector<Ciphertext<DCRTPoly>> EvalComparisonInner(const std::vector<Ciphertext<DCRTPoly>>& inputsOld, uint64_t k, 
				const EvalKey<DCRTPoly>& CKKStoFHEWswk, const Ciphertext<DCRTPoly>& FHEWtoCKKSswk, 
				CryptoContextImpl<DCRTPoly>& ccCKKSin, CryptoContextImpl<DCRTPoly>& ccCKKSout, 
				CryptoContextImpl<DCRTPoly>& ccCKKSlower, 
				BinFHEContext& m_ccLWE, // note that this is not const, to see whether this needs fix
				 const uint64_t& m_modulus_to,
				 int init_size, uint32_t m_bridgingUpperbound,
				 bool forConversionOnly = false, double pmin = -0.25, double pmax = 0.25,
				 bool diffTree = true
				 //bool dirReturn
                 ){
#if defined(BRIDGING_DEBUG)
  TimeVar total;
  TIC(total);
#endif
	if(!inputsOld.size()){
		OPENFHE_THROW(type_error, "Empty input FHEW ciphertext vector");
	}

    uint64_t inputW = inputsOld.size();
    uint64_t paddedW = 1;
    while(paddedW < inputW) paddedW <<= 1;
	int dim1 = findOPTratio(double(m_bridgingUpperbound));
	auto n = m_ccLWE.GetParams()->GetLWEParams()->Getn();
	int dim2 = findOPTratio(double(n));
	if(n != 512)
	{
		dim2 = 0;
	}

    uint64_t paddedK = 1; // Note: Still requires only the first k values are non-zero, and the rest (paddedk - k) values must be zeros.
    while(paddedK < k) paddedK <<= 1;

	uint64_t paddedDiff = 1;
    while(paddedDiff < inputW/2) paddedDiff <<= 1;
	
	std::vector<Ciphertext<DCRTPoly>> inputs(inputW);
    auto m_CTforPadding = ccCKKSin.getPaddingCT();
    size_t compress_size = inputs.size();
    if(!forConversionOnly){
        compress_size = inputs.size()/2*2;
    }
	for(size_t i = 0; i < compress_size; i++){
		inputs[i] = ccCKKSin.Compress(inputsOld[i], 3);
	}
    if(forConversionOnly){
        while(paddedW != inputs.size()){
                inputs.push_back(m_CTforPadding);
            }
    }    
	// return inputs;
	

	std::vector<Ciphertext<DCRTPoly>> diffs(inputs.size()/2);

	// First round is down with ccCKKS
	// Step 1: calculate diffs
	// cout << "step 1" << endl;
	if(forConversionOnly)
		diffs = inputs;
	else{
		if(diffTree){
			for(size_t j = 0; j < (inputs.size())/2*2; j+=2){
				// cout << j << " " << j+1 << " " << inputs.size() << endl;
				diffs[j/2] = ccCKKSin.EvalAdd(ccCKKSin.EvalNegate(inputs[j+1]), inputs[j]); // diff[j] = input[j] - input[j+k/2]
			}
		} else {
			for(size_t j = 0; j < inputs.size()/2; j++){
				diffs[j] = ccCKKSin.EvalAdd(ccCKKSin.EvalNegate(inputs[j+inputs.size()/2]), inputs[j]); // diff[j] = input[j] - input[j+k/2]
			}
		}
	}
	if(!forConversionOnly)
		inputs.clear();
	// return diffs;
	
	// Step 2: compress diffs into one CKKS ciphertext
    for(size_t j = 1; j < diffs.size(); j++){
		diffs[j] = ccCKKSin.EvalAdd(ccCKKSin.EvalAtIndex(diffs[j-1], paddedK), diffs[j]); 
	}
    diffs[diffs.size() - 1] = ccCKKSin.EvalAtIndex(diffs[diffs.size() - 1], paddedK);
    diffs[0] = diffs[diffs.size() - 1];
	for(size_t j = diffs.size(); j < paddedDiff; j++){
		diffs[0] = ccCKKSin.EvalAtIndex(diffs[0], paddedK); 
	}

	for(size_t j = 1; j < ccCKKSin.GetRingDimension()/2/(paddedDiff*paddedK); j*=2){
		diffs[0] = ccCKKSin.EvalAdd(ccCKKSin.EvalAtIndex(diffs[0], (paddedDiff*paddedK)*j), diffs[0]); 
	}
	// return diffs;
	// Step 3: CKKStoFHEW
	auto diffsize = diffs.size();
	// return diffs;
	diffs.resize(1);
	auto resLWEs = CKKStoFHEW(diffs[0], CKKStoFHEWswk, diffsize*paddedK/*, kp.secretKey, sk*/, ccCKKSlower, m_ccLWE, m_modulus_to, dim1);
	diffs.clear();
	paddedK/= 2;

    if(forConversionOnly){
        resLWEs.resize(inputW*paddedK);
    } else {
		resLWEs.resize(diffsize*paddedK);
	}
#if defined(BRIDGING_DEBUG)
  TimeVar t;
  TIC(t);
#endif

	std::vector<std::shared_ptr<LWECiphertextImpl>> resLWEoutput(resLWEs.size());
	if(!forConversionOnly){
// #pragma omp parallel for // num_threads(8) // parallelization doesn't work
		for(uint32_t i = 0; i < resLWEs.size(); i++){
            if (i % paddedK < k){
			    resLWEoutput[i] = m_ccLWE.EvalSignSchemeSwitching(resLWEs[i], m_modulus_to);
            }
            else{
                NativeVector a(m_ccLWE.GetParams()->GetLWEParams()->Getn(), m_modulus_to);
                NativeInteger b(m_modulus_to/4);
                resLWEoutput[i] = std::make_shared<LWECiphertextImpl>(LWECiphertextImpl(a, b));
            }
		}
	} else {
		resLWEoutput = resLWEs;
	}

#if defined(BRIDGING_DEBUG)
  cout << "FHEW sign time: " << TOC_MS(t) << " ms" << endl;
  TIC(t);
#endif

	// Step 5: FHEWtoCKKS, fix dimension to 0, result pmin = 0, pmax = 1
	Ciphertext<DCRTPoly> packedSEL;
	if(forConversionOnly){
		packedSEL = FHEWtoCKKS(resLWEs, FHEWtoCKKSswk, ccCKKSout, m_ccLWE.GetParams()->GetLWEParams()->Getn(), dim2, m_modulus_to, pmin, pmax, FHEWtoCKKSswk->GetLevel());
		packedSEL = ccCKKSout.EvalNegate(packedSEL);
	}
	else
		packedSEL = FHEWtoCKKS(resLWEoutput, FHEWtoCKKSswk, ccCKKSout, m_ccLWE.GetParams()->GetLWEParams()->Getn(), dim2, m_modulus_to, 0, 1, FHEWtoCKKSswk->GetLevel());

	std::vector<Ciphertext<DCRTPoly>> expandedSEL(diffsize);
    if(forConversionOnly){
        expandedSEL.resize(inputW);
    }
	if(diffsize == 1){
#if defined(BRIDGING_DEBUG)
  cout << "Total Comparison Time: " << TOC_MS(total) << " ms\n" << endl;
#endif
		expandedSEL[0] = packedSEL;
		return expandedSEL;
	}
	std::vector<std::complex<double>> x(ccCKKSout.GetRingDimension()/2, 0); // first k are 1's and the rest are 0's
	for(size_t i = 0; i < k; i++)
		x[i] = 1;
  	Plaintext ptxt = ccCKKSout.MakeCKKSPackedPlaintext(x);
	for(size_t i = 0; i < expandedSEL.size(); i++){
		expandedSEL[i] = ccCKKSout.EvalMult(packedSEL, ptxt);// TODO: should be a compress here, modify later, may not be needed due to compressions at other places
		ccCKKSout.RescaleInPlace(expandedSEL[i]);
		if(i != expandedSEL.size()-1)
			packedSEL = ccCKKSout.EvalAtIndex(packedSEL, paddedK); 
	}

#if defined(BRIDGING_DEBUG)
  cout << "Total Comparison Time: " << TOC_MS(total) << " ms\n" << endl;
#endif
	return expandedSEL;
}

bool checkInputSize(uint64_t w, uint64_t k, uint64_t bound){
	uint64_t paddedK = 1;
	uint64_t paddedW = 1;
	while(paddedW < w) paddedW <<= 1;
    while(paddedK < k) paddedK <<= 1;
	if(paddedK*paddedW > bound){
		return false;
	}
	return true;
}

template <>
Ciphertext<DCRTPoly> CryptoContextImpl<DCRTPoly>::EvalArgMinOneHot(const Ciphertext<DCRTPoly>& input, uint64_t w, uint64_t k,
                                        double normalizing_coeff, bool zero_out) {
	if(!checkInputSize(w, k, m_bridgingUpperbound)){
		OPENFHE_THROW(config_error, "Input for ArgMax must satisfy input_vector_size_padded_to_nearest_power_of_two*k_padded_to_nearest_power_of_two <= m_bridgingUpperbound");
	}
	if(k != 1){
		OPENFHE_THROW(config_error, "Not surpported for k != 1");
	}


	std::vector<Ciphertext<DCRTPoly>> inputVec(2);
	auto copy = input; //this->Compress(input, int(ceil(log2(w)))+2);
	if (normalizing_coeff != 0){
		if(zero_out){
			std::vector<std::complex<double>> tempScale(this->GetRingDimension()/2, 0);
			for(size_t i = 0; i < w; i++){
				tempScale[i] = -1./normalizing_coeff;
			}
    		auto LWEskPlain = this->MakeCKKSPackedPlaintext(tempScale);
			copy = this->EvalMult(copy, LWEskPlain);  
		} else {
			copy = this->EvalMult(copy, -1./normalizing_coeff);  
		}
		this->RescaleInPlace(copy);
	}
	std::vector<std::complex<double>> toMakeTheRestSmallestPossible(this->GetRingDimension()/2, 0.25);
	for(size_t i = 0; i < w; i++){
		toMakeTheRestSmallestPossible[i] = 0;
	}
    auto tempPlain = this->MakeCKKSPackedPlaintext(toMakeTheRestSmallestPossible);
	copy = this->EvalAdd(copy, tempPlain);  

	size_t counter = 1;
	while(counter < w) counter <<= 1;

	std::vector<std::complex<double>> theOnes(this->GetRingDimension()/2, 1);
    auto ret = this->MakeCKKSPackedPlaintext(theOnes);
	Ciphertext<DCRTPoly> retCT;

	auto swkCounter = 0;
	while(counter > 1){
		counter /= 2;
		std::vector<std::complex<double>> first1s(this->GetRingDimension()/2, 0);
		for(size_t i = 0; i < counter; i++){
			first1s[i] = 1.;
		}
    	auto first1sPlain = this->MakeCKKSPackedPlaintext(first1s);
		inputVec[0] = this->EvalMult(copy, first1sPlain);
		this->RescaleInPlace(inputVec[0]);
		auto tempcopy = this->EvalAtIndex(copy, counter);
		inputVec[1] = this->EvalMult(tempcopy, first1sPlain);
		this->RescaleInPlace(inputVec[1]);
		auto tempswk = m_FHEWtoCKKSswkOutside;
		if(swkCounter){
			tempswk = this->Compress(m_FHEWtoCKKSswkOutside, m_FHEWtoCKKSswkOutside->GetLevel() - swkCounter);
		} 
		auto selectors = EvalComparisonInner(inputVec, counter*2, m_CKKStoFHEWswkOutside, tempswk, 
										*this, *this, *m_ccCKKSlower, m_ccLWE, m_modulus_to, 
										m_init_size_inner, m_bridgingUpperbound);
		// Compress selector to the level of theSelector
		auto selNeg = this->EvalNegate(selectors[0]);
		// return selNeg;
		for(size_t i = 0; i < counter; i++){
			first1s[i] = 1.;
		}
    	auto first1sPlain2 = this->MakeCKKSPackedPlaintext(first1s);
		selNeg = this->EvalAdd(selNeg, first1sPlain2);
		if(counter != 1){
			auto sel1 = this->EvalMult(copy, selectors[0]);
			auto rotSelNeg = this->EvalAtIndex(selNeg, -int(counter));
			auto sel2 = this->EvalMult(copy, rotSelNeg);
			sel2 = this->EvalAtIndex(sel2, int(counter));
			copy = this->EvalAdd(sel1, sel2);
			this->RescaleInPlace(copy);
		}


		auto div = uint64_t(ceil(double(w)/double(counter)));
		Ciphertext<DCRTPoly> theSelector;
		selectors[0] = this->Compress(selectors[0], m_init_size_inner - copy->GetLevel() + 1);
		for(size_t i = 0; i < div; i ++){
			if(i == 0){
				theSelector = selectors[0];
				continue;
			} 
			if(i&1){
				int tempRotSteps = -int(counter)*2;
				if(i == 1)
					tempRotSteps = -int(counter);
				selNeg = this->EvalAtIndex(selNeg, tempRotSteps);
				theSelector = this->EvalAdd(theSelector, selNeg);
			} else {
				int tempRotSteps = -int(counter)*2;
				selectors[0] = this->EvalAtIndex(selectors[0], tempRotSteps);
				theSelector = this->EvalAdd(theSelector, selectors[0]);
			}
		}
		// return theSelector;
		if(swkCounter == 0){
			retCT = this->EvalMult(theSelector, ret);
			this->RescaleInPlace(retCT);
		} else {
			retCT = this->EvalMult(retCT, theSelector);
			this->RescaleInPlace(retCT);
		}
		swkCounter++;
		// return theSelector;
	}
	return retCT;
}

}  // namespace lbcrypto