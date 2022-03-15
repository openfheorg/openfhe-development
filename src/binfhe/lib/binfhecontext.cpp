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
  Implementation file for Boolean Circuit FHE context class
 */

#include "binfhecontext.h"

namespace lbcrypto {

void BinFHEContext::GenerateBinFHEContext(uint32_t n, uint32_t N,
                                          const NativeInteger &q,
                                          const NativeInteger &Q, double std,
                                          uint32_t baseKS, uint32_t baseG,
                                          uint32_t baseR, BINFHEMETHOD method) {
  auto lweparams = std::make_shared<LWECryptoParams>(n, N, q, Q, Q, std, baseKS);
  m_params =
      std::make_shared<RingGSWCryptoParams>(lweparams, baseG, baseR, method);
}



void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set,
                                          bool arbFunc, uint32_t logQ, long N,  
                                          BINFHEMETHOD method, bool timeOptimization) {
  
  if(method == AP){
    std::string errMsg =
             "Currently only support for method = GINX.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }
  if(set != STD128 && set != TOY){
    std::string errMsg =
             "Currently only support for STD128 and TOY.";
    PALISADE_THROW(not_implemented_error, errMsg);
  }

  SecurityLevel  sl = HEStd_128_classic;

  m_timeOptimization = timeOptimization;
  auto logQprime = 27;
  uint32_t baseG = 0;
  if(logQ == 11){
    baseG = 1<<5;
  } else if (logQ > 29) {
    std::string errMsg =
             "Error: Don't support logQ > 29.";
    PALISADE_THROW(not_implemented_error, errMsg);
    return;
  } else if (logQ > 25) {
    baseG = 1<<14;
    logQprime = 54;
  } else if (logQ > 16) {
    baseG = 1<<18;
    logQprime = 54;
  } else if (logQ > 11) {
    baseG = 1<<27;
    logQprime = 54;
  } else {
    std::string errMsg =
              "Error: Don't support logQ < 11.";
    PALISADE_THROW(not_implemented_error, errMsg);
    return;
  }

  uint32_t ringDim = StdLatticeParm::FindRingDim(HEStd_ternary,sl,logQprime); // choose minimum ringD satisfying sl and Q
  if (N >= ringDim){ // if specified some larger N, security is also satisfied
    ringDim = N;
  }
  NativeInteger Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(logQprime, ringDim), ringDim); // find prime Q for NTT
  long q = ringDim * 2; // q = N*2 by default for maximum plaintext space
  if(arbFunc) q = ringDim; // if needed for arbitrary function evlauation, q = ringDim/2

  long n = 1305;
  uint64_t qKS = 1 << 30; 
  qKS <<= 5;

  if(set == TOY){
    n = 32;
  }

  auto lweparams = std::make_shared<LWECryptoParams>(n, ringDim, q, Q.ConvertToInt(), qKS, 3.19, 32);
  m_params =
      std::make_shared<RingGSWCryptoParams>(lweparams, baseG, 23, method, ((logQ != 11)&&timeOptimization));
  
#if defined(BINFHE_DEBUG)
  std::cout << ringDim << " " << Q << << " " << n << " " << q << " " << baseG <<std::endl;
#endif
  return;
}



void BinFHEContext::GenerateBinFHEContext(BINFHEPARAMSET set,
                                          BINFHEMETHOD method) {

  shared_ptr<LWECryptoParams> lweparams;
  NativeInteger Q;
  switch (set) {
    case TOY:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 1024),
                                       1024);
      lweparams = std::make_shared<LWECryptoParams>(64, 512, 512, Q, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 23, method);
      break;
    case STD128_AP:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 32, method);
      break;
    case STD128_APOPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(502, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 9, 32, method);
      break;
    case STD128:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 23, method);
      break;
    case STD128_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(27, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(502, 1024, 1024, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 23, method);
      break;
    case STD192:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 19, 3.19, 28);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 27, 23, method);
      break;
    case STD192_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(805, 2048, 1024, Q, 1 << 15, 3.19, 1 << 5);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 27, 23, method);
      break;
    case STD256:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 2048, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD256_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(990, 2048, 2048, Q, 1 << 14, 3.19, 1 << 7);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD128Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 25, 3.19, 32);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 23, method);
      break;
    case STD128Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(585, 2048, 1024, Q, 1 << 15, 3.19, 32);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 23, method);
      break;
    case STD192Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1024, 2048, 1024, Q, 1 << 17, 3.19, 64);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD192Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(50, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(875, 2048, 1024, Q, 1 << 15, 3.19, 1 << 5);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 25, 32, method);
      break;
    case STD256Q:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(2048, 2048, 1024, Q, 1 << 16, 3.19, 16);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 27, 32, method);
      break;
    case STD256Q_OPT:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(54, 4096),
                                       4096);
      lweparams =
          std::make_shared<LWECryptoParams>(1225, 2048, 1024, Q, 1 << 16, 3.19, 16);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 27, 32, method);
      break;
    case SIGNED_MOD_TEST:
      Q = PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(28, 2048),
                                       2048);
      lweparams =
          std::make_shared<LWECryptoParams>(512, 1024, 512, Q, Q, 3.19, 25);
      m_params =
          std::make_shared<RingGSWCryptoParams>(lweparams, 1 << 7, 23, method);
      break;
    default:
      std::string errMsg = "ERROR: No such parameter set exists for FHEW.";
      PALISADE_THROW(config_error, errMsg);
  }
}

LWEPrivateKey BinFHEContext::KeyGen(NativeInteger DiffQ) const {
  if(DiffQ > m_params->GetLWEParams()->Getq()){
    auto q = m_params->GetLWEParams()->Getq();
    this->ChangeQ(DiffQ);
    auto ret = m_LWEscheme->KeyGen(m_params->GetLWEParams());
    this->ChangeQ(q);
    return ret;
  }
  return m_LWEscheme->KeyGen(m_params->GetLWEParams());
}

LWEPrivateKey BinFHEContext::KeyGenN() const {
  return m_LWEscheme->KeyGenN(m_params->GetLWEParams());
}

LWECiphertext BinFHEContext::Encrypt(ConstLWEPrivateKey sk,
                                     const LWEPlaintext &m,
                                     BINFHEOUTPUT output,
                                     LWEPlaintextModulus p,
                                     NativeInteger DiffQ) const {
  auto q = m_params->GetLWEParams()->Getq();
  if(DiffQ > q){
    this->ChangeQ(DiffQ);
  }
  LWECiphertext ct;

  if ((output == FRESH) || (p != 4)) {
    ct = m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m, p);
  } else {
    ct = m_LWEscheme->Encrypt(m_params->GetLWEParams(), sk, m, p);
    ct = m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct, m_LWEscheme);
  }

  if(DiffQ > q){
    this->ChangeQ(q);
  }
  return ct;
}

void BinFHEContext::Decrypt(ConstLWEPrivateKey sk, ConstLWECiphertext ct,
                            LWEPlaintext *result, LWEPlaintextModulus p,
                            NativeInteger DiffQ) const {
  auto q = m_params->GetLWEParams()->Getq();
  // std::cout << "??? " << DiffQ << " " << q << std::endl;
  if(DiffQ != 0){
    // std::cout << "??? " << DiffQ << " " << q << std::endl;
    this->ChangeQ(DiffQ);
    LWEPrivateKeyImpl skp(sk->GetElement());
    std::shared_ptr<LWEPrivateKeyImpl> skpptr = std::make_shared<LWEPrivateKeyImpl>(skp);
    skpptr->switchModulus(DiffQ);
    m_LWEscheme->Decrypt(m_params->GetLWEParams(), skpptr, ct, result, p);
    this->ChangeQ(q);
    return;
  } else {
    m_LWEscheme->Decrypt(m_params->GetLWEParams(), sk, ct, result, p);
    return;
  }
}

std::shared_ptr<LWESwitchingKey> BinFHEContext::KeySwitchGen(
    ConstLWEPrivateKey sk, ConstLWEPrivateKey skN) const {
  return m_LWEscheme->KeySwitchGen(m_params->GetLWEParams(), sk, skN);
}

void BinFHEContext::BTKeyGen(ConstLWEPrivateKey sk, NativeInteger DiffQ) {
  auto q = m_params->GetLWEParams()->Getq();
  if(DiffQ > q){
    this->ChangeQ(DiffQ);
  }

  auto temp = m_params->GetBaseG();

  if(m_timeOptimization){
    auto gpowermap = m_params->GetGPowerMap();
    for(std::map<uint32_t, std::vector<NativeInteger>>::iterator it = gpowermap.begin(); it != gpowermap.end(); ++it){
      m_params->Change_BaseG(it->first);
      m_BTKey_map[it->first] = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
    }
    m_params->Change_BaseG(temp);
  }

  if(m_BTKey_map.size()!=0){
    m_BTKey = m_BTKey_map[temp];
  } else {
    m_BTKey = m_RingGSWscheme->KeyGen(m_params, m_LWEscheme, sk);
    m_BTKey_map[temp] = m_BTKey;
  }

  if(DiffQ > q){
    this->ChangeQ(q);
  }

  return;
}

LWECiphertext BinFHEContext::EvalBinGate(const BINGATE gate,
                                         ConstLWECiphertext ct1,
                                         ConstLWECiphertext ct2) const {
  return m_RingGSWscheme->EvalBinGate(m_params, gate, m_BTKey, ct1, ct2,
                                      m_LWEscheme);
}

LWECiphertext BinFHEContext::Bootstrap(ConstLWECiphertext ct1) const {
  return m_RingGSWscheme->Bootstrap(m_params, m_BTKey, ct1, m_LWEscheme);
}

LWECiphertext BinFHEContext::EvalNOT(ConstLWECiphertext ct) const {
  return m_RingGSWscheme->EvalNOT(m_params, ct);
}

LWECiphertext BinFHEContext::EvalFunc(ConstLWECiphertext ct1,
    const vector<NativeInteger>& LUT) const {
  NativeInteger beta = GetBeta();
  return m_RingGSWscheme->EvalFunc(m_params, m_BTKey, ct1, m_LWEscheme, LUT, beta, 0);
}

LWECiphertext BinFHEContext::EvalFloor(ConstLWECiphertext ct1, const uint32_t roundbits) const{
  
  auto q = m_params->GetLWEParams()->Getq().ConvertToInt();
  if(roundbits != 0){
    NativeInteger newp = this->GetMaxPlaintextSpace();
    ChangeQ(q/newp*(1<<roundbits)); 
  }
  NativeInteger beta = GetBeta();
  auto res = m_RingGSWscheme->EvalFloor(m_params, m_BTKey, ct1, m_LWEscheme, beta, q);
  ChangeQ(q); 
  return res;
}

LWECiphertext BinFHEContext::EvalSign(ConstLWECiphertext ct1,
    const NativeInteger bigger_q) {
  auto params = std::make_shared<RingGSWCryptoParams>(*m_params);
  NativeInteger beta = GetBeta();
  return m_RingGSWscheme->EvalSign(params, m_BTKey_map, ct1, m_LWEscheme, beta, bigger_q);
}

vector<LWECiphertext> BinFHEContext::EvalDecomp(ConstLWECiphertext ct1,
    const NativeInteger bigger_q) {
  NativeInteger beta = GetBeta();
  return m_RingGSWscheme->EvalDecomp(m_params, m_BTKey_map, ct1, m_LWEscheme, beta, bigger_q);
}

vector<NativeInteger> BinFHEContext::GenerateLUTviaFunction(NativeInteger(*f) (NativeInteger m, NativeInteger p),
                                      NativeInteger p){
  auto params = GetParams();

  if(ceil(log2(p.ConvertToInt())) != floor(log2(p.ConvertToInt()))){
      std::string errMsg =
          "ERROR: Only support plaintext space to be power-of-two.";
      PALISADE_THROW(not_implemented_error, errMsg);
      return vector<NativeInteger>(0);
  }

  NativeInteger q = params->GetLWEParams()->Getq();

  NativeInteger interval = q/p;
  NativeInteger outerval = interval;
  vector<NativeInteger> vec(q.ConvertToInt());
  
  for(NativeInteger i = 0; i < q; i+=1){
      if(f(i/interval, p) >= p){
          std::string errMsg =
          "ERROR: input function should output in Z_{p_output}.";
          PALISADE_THROW(not_implemented_error, errMsg);
          return vector<NativeInteger>(0);
      }
      vec[i.ConvertToInt()] = f(i/interval, p)*outerval;
  }
  return vec;
}

}  // namespace lbcrypto
