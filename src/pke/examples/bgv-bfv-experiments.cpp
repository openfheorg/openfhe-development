// @file  bgv-bfv-experiments.cpp - Advanced examples for BGV and BFV.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

// Define PROFILE to enable TIC-TOC timing measurements
#define PROFILE

#include "openfhe.h"
#include "gen-cryptocontext.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "scheme/bgvrns/cryptocontext-bgvrns.h"

using namespace lbcrypto;

static usint schemeBGV = 0;
static usint schemeBFV = 1;

CryptoContext<DCRTPoly> GenerateContextBGV(usint ptm,
                                        usint numAdd,
                                        usint multDepth,
                                        usint ringDim,
                                        KeySwitchTechnique ksTech, bool isTowBig);

CryptoContext<DCRTPoly> GenerateContextBFV(usint ptm,
                                        usint numAdd,
                                        usint multDepth,
                                        usint numks,
                                        usint ringDim,
                                        KeySwitchTechnique ksTech,
                                        bool isTowBig,
                                        usint dcrtBits,
                                        EncryptionTechnique encMethod,
                                        MultiplicationTechnique multMethod);

void EvalNoiseBGV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, usint ptm, double& noise, double& logQ);
void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm, double& noise, double& logQ, EncryptionTechnique encMethod);
void EvalNoiseBFVB(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm, double& noise, double& logQ, EncryptionTechnique encMethod);

void Check(std::vector<int64_t> encvec, std::vector<int64_t> decvec, usint ptm);
void Head();
void Statistics(usint N, usint dcrtBits, double noise, double logQ, double time);

void BinaryTreeDemo(usint ptm, usint logsize, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig);
void ChainMultDemo(usint ptm, usint logsize, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig);
void FullPolyDemo(usint ptm, usint coeffBound, usint k, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig);
void EvalSumDemo(usint ptm, usint logringDim, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig);
void HorzInnerProdDemo(usint ptm, usint logringDim, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig);

void BinaryTreeDemoAll(usint ptm, usint logringDim, usint multDepth, bool isNumBig);
void ChainMultDemoAll(usint ptm, usint logringDim, usint multDepth, bool isNumBig);
void FullPolyDemoAll(usint ptm, usint coeffBound, usint logringDim, usint multDepth, bool isNumBig);
void EvalSumDemoAll(usint ptm, bool isNumBig);
void HorzInnerProdDemoAll(usint ptm, bool isNumBig);

void test2() {
  usint ptm = 2;

  BinaryTreeDemoAll(ptm, 0, 0, false);
  FullPolyDemoAll(ptm, 1, 0, 0, false);

  //BinaryTreeDemoAll(ptm, 0, 0, true);
  //FullPolyDemoAll(ptm, 1, 0, 0, true);
}

void test16() {
  usint ptm = 65537;

  //BinaryTreeDemoAll(ptm, 0, 0, false);
  FullPolyDemoAll(ptm, 16, 0, 0, false);

  //BinaryTreeDemoAll(ptm, 0, 0, true);
  FullPolyDemoAll(ptm, 16, 0, 0, true);
}

void test30() {
  NativeInteger q = FirstPrime<NativeInteger>(30, 65536);
  usint ptm = PreviousPrime(q, 65536).ConvertToInt();

  //BinaryTreeDemoAll(ptm, 0, 0, false);
  FullPolyDemoAll(ptm, 16, 0, 0, false);

  //BinaryTreeDemoAll(ptm, 0, 0, true);
  FullPolyDemoAll(ptm, 16, 0, 0, true);
}

int main(int argc, char* argv[]) {
  test2();
  //test16();
  //test30();

  return 0;
}

CryptoContext<DCRTPoly> GenerateContextBGV(usint ptm,
                                        usint numAdd, usint multDepth,
                                        usint ringDim,
                                        KeySwitchTechnique ksTech,
                                        bool isTowBig) {
  SecurityLevel securityLevel = HEStd_128_classic;
  SecretKeyDist secretKeyDist = GAUSSIAN;

  usint dcrtBits;
  if(ringDim > 0) {
    dcrtBits = 3 + static_cast<usint>(ceil(log2(ringDim) + log2(ptm) + log2(numAdd + 1)));
  } else {
    if(ptm == 2) {
      dcrtBits = 3 + static_cast<usint>(ceil(1.25*13 + log2(ptm) + log2(numAdd + 1)));
    } else {
      dcrtBits = 3 + static_cast<usint>(ceil(13 + log2(ptm) + log2(numAdd + 1)));
    }
  }
  usint firstModSize;
  if(ringDim > 0) {
    firstModSize = 2 + static_cast<usint>(ceil(log2(ringDim)/2 + log2(ptm) + log2(numAdd + 1)));
  } else {
    if(ptm == 2) {
      firstModSize = 2 + static_cast<usint>(ceil(1.25*13/2 + log2(ptm) + log2(numAdd + 1)));
    } else {
      firstModSize = 2 + static_cast<usint>(ceil(13./2 + log2(ptm) + log2(numAdd + 1)));
    }
  }

  CryptoContext<DCRTPoly> cc(nullptr);
  CCParams<CryptoContextBGVRNS> parameters;
  multDepth = multDepth == 0 ? 1 : multDepth;
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetPlaintextModulus(ptm);
  parameters.SetSecurityLevel(securityLevel);
  parameters.SetStandardDeviation(3.19);
  parameters.SetMaxDepth(0);
  parameters.SetSecretKeyDist(secretKeyDist);
  parameters.SetKeySwitchTechnique(ksTech);
  parameters.SetRingDim(ringDim);
  parameters.SetFirstModSize(firstModSize);
  parameters.SetScalingFactorBits(dcrtBits);
  parameters.SetBatchSize(0);
  parameters.SetRescalingTechnique(FLEXIBLEAUTOEXT);
  parameters.SetEvalAddCount(numAdd);

  cc = GenCryptoContext(parameters);

  cc->Enable(PKE);
  cc->Enable(LEVELEDSHE);

  return cc;
}

CryptoContext<DCRTPoly> GenerateContextBFV(usint ptm,
                                        usint numAdd,
                                        usint multDepth,
                                        usint numks,
                                        usint ringDim,
                                        KeySwitchTechnique ksTech,
                                        bool isTowBig,
                                        usint dcrtBits,
                                        EncryptionTechnique encMethod,
                                        MultiplicationTechnique multMethod) {
  SecurityLevel securityLevel = HEStd_128_classic;
  SecretKeyDist secretKeyDist = GAUSSIAN;

  CryptoContext<DCRTPoly> cc(nullptr);
  CCParams<CryptoContextBFVRNS> parameters;
  multDepth = multDepth == 0 ? 1 : multDepth;
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetPlaintextModulus(ptm);
  parameters.SetSecurityLevel(securityLevel);
  parameters.SetStandardDeviation(3.19);
  parameters.SetMaxDepth(2);
  parameters.SetSecretKeyDist(secretKeyDist);
  parameters.SetKeySwitchTechnique(ksTech);
  parameters.SetRingDim(ringDim);
  parameters.SetScalingFactorBits(dcrtBits);
  parameters.SetBatchSize(0);
  parameters.SetEncryptionTechnique(encMethod);
  parameters.SetMultiplicationTechnique(multMethod);
  parameters.SetEvalAddCount(numAdd);
  parameters.SetEvalMultCount(multDepth);
  parameters.SetKeySwitchCount(numks);

  cc = GenCryptoContext(parameters);

  cc->Enable(PKE);
  cc->Enable(LEVELEDSHE);

  return cc;
}

void BinaryTreeDemoAll(usint ptm, usint logringDim, usint multDepth, bool isNumBig) {
  std::cerr << "-----------------------------------" << std::endl;
  std::cerr << "Binary Tree Demo: ";
  if(logringDim == 0) {
    std::cerr << "ringDimBits: dynamic";
  } else {
    std::cerr << "ringDimBits: " << logringDim;
  }
  if(multDepth == 0) {
    std::cerr << ", multDepth: dynamic";
  } else {
    std::cerr << ", multDepth: " << multDepth;
  }
  std::cerr << std::endl;
  Head();
  for (usint logsize : {1, 2, 3, 4, 5, 6, 7}) {
    std::cerr << logsize;
    BinaryTreeDemo(ptm, logsize, logringDim, logsize + 1, STANDARD, BEHZ, schemeBFV, isNumBig);
    BinaryTreeDemo(ptm, logsize, logringDim, logsize + 1, STANDARD, HPS, schemeBFV, isNumBig);
    BinaryTreeDemo(ptm, logsize, logringDim, logsize + 1, POVERQ, HPSPOVERQ, schemeBFV, isNumBig);
    BinaryTreeDemo(ptm, logsize, logringDim, logsize + 1, POVERQ, HPSPOVERQLEVELED, schemeBFV, isNumBig);
    BinaryTreeDemo(ptm, logsize, logringDim, logsize + 1, STANDARD, HPS, schemeBGV, isNumBig);
    std::cerr << " \\\\" << std::endl;
  }
  std::cerr << "-----------------------------------" << std::endl;
}

void ChainMultDemoAll(usint ptm, usint logringDim, usint multDepth, bool isNumBig) {
  std::cerr << "-----------------------------------" << std::endl;
  std::cerr << "Chain Mult Demo: ";
  if(logringDim == 0) {
    std::cerr << "ringDimBits: dynamic";
  } else {
    std::cerr << "ringDimBits: " << logringDim;
  }
  if(multDepth == 0) {
    std::cerr << ", multDepth: dynamic";
  } else {
    std::cerr << ", multDepth: " << multDepth;
  }
  std::cerr << std::endl;
  Head();
  for (usint logsize : {2, 4, 6, 8, 10, 12}) {
    std::cerr << logsize;
    ChainMultDemo(ptm, logsize, logringDim, multDepth, STANDARD, BEHZ, schemeBFV, isNumBig);
    ChainMultDemo(ptm, logsize, logringDim, multDepth, STANDARD, HPS, schemeBFV, isNumBig);
    ChainMultDemo(ptm, logsize, logringDim, multDepth, POVERQ, HPSPOVERQ, schemeBFV, isNumBig);
    ChainMultDemo(ptm, logsize, logringDim, multDepth, POVERQ, HPSPOVERQLEVELED, schemeBFV, isNumBig);
    ChainMultDemo(ptm, logsize, logringDim, multDepth, STANDARD, HPS, schemeBGV, isNumBig);
    std::cerr << " \\\\" << std::endl;
  }
  std::cerr << "-----------------------------------" << std::endl;
}

void FullPolyDemoAll(usint ptm, usint coeffBound, usint logringDim, usint multDepth, bool isNumBig) {
  std::cerr << "-----------------------------------" << std::endl;
  std::cerr << "Polynomial Demo: ";
  if(logringDim == 0) {
    std::cerr << "ringDimBits: dynamic";
  } else {
    std::cerr << "ringDimBits: " << logringDim;
  }
  if(multDepth == 0) {
    std::cerr << ", multDepth: dynamic";
  } else {
    std::cerr << ", multDepth: " << multDepth;
  }
  std::cerr << std::endl;
  Head();
  for (usint size : {2, 4, 8, 16, 32, 48, 64}) {
    std::cerr << size;
    FullPolyDemo(ptm, coeffBound, size, logringDim, multDepth, STANDARD, BEHZ, schemeBFV, isNumBig);
    FullPolyDemo(ptm, coeffBound, size, logringDim, multDepth, STANDARD, HPS, schemeBFV, isNumBig);
    FullPolyDemo(ptm, coeffBound, size, logringDim, multDepth, POVERQ, HPSPOVERQ, schemeBFV, isNumBig);
    FullPolyDemo(ptm, coeffBound, size, logringDim, multDepth, POVERQ, HPSPOVERQLEVELED, schemeBFV, isNumBig);
    FullPolyDemo(ptm, coeffBound, size, logringDim, multDepth, STANDARD, HPS, schemeBGV, isNumBig);
    std::cerr << " \\\\" << std::endl;
  }
  std::cerr << "-----------------------------------" << std::endl;
}

void EvalSumDemoAll(usint ptm, bool isNumBig) {
  std::cerr << "-----------------------------------" << std::endl;
  std::cerr << "Eval Sum Demo" << std::endl;
  Head();
  for (usint logRingDim : {14, 15}) {
    std::cerr << logRingDim;
    EvalSumDemo(ptm, logRingDim, STANDARD, BEHZ, schemeBFV, isNumBig);
    EvalSumDemo(ptm, logRingDim, STANDARD, HPS, schemeBFV, isNumBig);
    EvalSumDemo(ptm, logRingDim, POVERQ, HPSPOVERQ, schemeBFV, isNumBig);
    EvalSumDemo(ptm, logRingDim, POVERQ, HPSPOVERQLEVELED, schemeBFV, isNumBig);
    EvalSumDemo(ptm, logRingDim, STANDARD, HPS, schemeBGV, isNumBig);
    std::cerr << " \\\\" << std::endl;
  }
  std::cerr << "-----------------------------------" << std::endl;
}

void HorzInnerProdDemoAll(usint ptm, bool isNumBig) {
  std::cerr << "-----------------------------------" << std::endl;
  std::cerr << "Eval Horizontal Inner Product Demo" << std::endl;
  Head();
  for (usint logRingDim : {13, 14, 15}) {
    std::cerr << logRingDim;
    HorzInnerProdDemo(ptm, logRingDim, STANDARD, BEHZ, schemeBFV, isNumBig);
    HorzInnerProdDemo(ptm, logRingDim, STANDARD, HPS, schemeBFV, isNumBig);
    HorzInnerProdDemo(ptm, logRingDim, POVERQ, HPSPOVERQ, schemeBFV, isNumBig);
    HorzInnerProdDemo(ptm, logRingDim, POVERQ, HPSPOVERQLEVELED, schemeBFV, isNumBig);
    HorzInnerProdDemo(ptm, logRingDim, STANDARD, HPS, schemeBGV, isNumBig);
    std::cerr << " \\\\" << std::endl;
  }
  std::cerr << "-----------------------------------" << std::endl;
}

void BinaryTreeDemo(usint ptm, usint logsize, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig) {
  if (multDepth == 0) {
    multDepth = logsize;
  }
  usint ringDim = 0;
  if(logringDim > 0) {
    ringDim = 1 << logringDim;
  }
  usint numAdd = 0;

  CryptoContext<DCRTPoly> cc =
      scheme == schemeBGV ? GenerateContextBGV(ptm, numAdd, multDepth, ringDim, HYBRID, isTowBig)
    : GenerateContextBFV(ptm, numAdd, multDepth, 0, ringDim, HYBRID, isTowBig, 60, encMethod, multMethod);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  usint N = cc->GetRingDimension();
  usint size = (ptm == 2) ? 1 : N;

  usint treesize = 1 << logsize;
  std::vector<Ciphertext<DCRTPoly>> cvec(treesize);
  std::vector<int64_t> encvec(size, 1);
  for (usint i = 0; i < treesize; ++i) {
    std::vector<int64_t> x(size);
    for (usint j = 0; j < size; ++j) {
      x[j] = rand() % ptm;
      encvec[j] *= x[j];
      encvec[j] %= ptm;
    }
    Plaintext ptxt = (ptm == 2) ?
        cc->MakeCoefPackedPlaintext(x) :
        cc->MakePackedPlaintext(x);
    cvec[i] = cc->Encrypt(keys.publicKey, ptxt);
  }

  TimeVar t;
  TIC(t);
  double time;
  Ciphertext<DCRTPoly> cRes;
  if(true) {
    for (usint i = (treesize >> 1); i >= 1; i >>= 1) {
      for (usint j = 0; j < i; ++j) {
        cvec[j] = cc->EvalMult(cvec[j], cvec[j + i]);
  //      if(isBGV) cvec[j] = cc->Rescale(cvec[j]);
      }
    }

    time = TOC_US(t);
    cRes = cvec[0]->Clone();
  } else {
    cRes = cc->EvalMultMany(cvec);
    time = TOC_US(t);
  }

  Plaintext result;
  cc->Decrypt(keys.secretKey, cRes, &result);
  std::vector<int64_t> decvec = (ptm == 2) ?
      result->GetCoefPackedValue() :
      result->GetPackedValue();

  Plaintext dRes = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(decvec) :
      cc->MakePackedPlaintext(decvec);

  double noise = 0, logQ = 0;
  if (scheme == schemeBGV) {
    EvalNoiseBGV(keys.secretKey, cRes, ptm, noise, logQ);
  } else if (multMethod != BEHZ) {
    EvalNoiseBFV(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  } else {
    EvalNoiseBFVB(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  }
  Check(encvec, decvec, ptm);
  usint dcrtBits;
  if (scheme == schemeBGV)
      dcrtBits = cc->GetElementParams()->GetParams()[1]->GetModulus().GetMSB();
  else
      dcrtBits = cc->GetElementParams()->GetParams()[0]->GetModulus().GetMSB();
  Statistics(N, dcrtBits, noise, logQ, time);
}

void ChainMultDemo(usint ptm, usint logsize, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig) {
  if (multDepth == 0) {
    multDepth = logsize;
  }
  usint ringDim = 0;
  if(logringDim > 0) {
    ringDim = 1 << logringDim;
  }
  usint numAdd = 0;
  CryptoContext<DCRTPoly> cc =
      scheme == schemeBGV ? GenerateContextBGV(ptm, numAdd, multDepth, ringDim, HYBRID, isTowBig)
    : GenerateContextBFV(ptm, numAdd, multDepth, 0, ringDim, HYBRID, isTowBig, 60, encMethod, multMethod);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  usint N = cc->GetRingDimension();
  usint size = (ptm == 2) ? 1 : N;

  std::vector<Ciphertext<DCRTPoly>> cvec(logsize + 1);
  std::vector<int64_t> encvec(size, 1);
  for (usint i = 0; i < logsize + 1; ++i) {
    std::vector<int64_t> x(size);
    for (usint j = 0; j < size; ++j) {
      x[j] = rand() % ptm;
      encvec[j] *= x[j];
      encvec[j] %= ptm;
    }
    Plaintext ptxt = (ptm == 2) ?
        cc->MakeCoefPackedPlaintext(x) :
        cc->MakePackedPlaintext(x);
    cvec[i] = cc->Encrypt(keys.publicKey, ptxt);
  }

  TimeVar t;
  TIC(t);
  double time;
  Ciphertext<DCRTPoly> cRes;
  for (usint i = 1; i < logsize + 1; ++i) {
    cvec[0] = cc->EvalMult(cvec[0], cvec[i]);
  }

  time = TOC_US(t);
  cRes = cvec[0]->Clone();
  Plaintext result;
  cc->Decrypt(keys.secretKey, cRes, &result);
  std::vector<int64_t> decvec = (ptm == 2) ?
      result->GetCoefPackedValue() :
      result->GetPackedValue();
  Plaintext dRes = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(decvec) :
      cc->MakePackedPlaintext(decvec);
  double noise = 0, logQ = 0;
  if (scheme == schemeBGV) {
    EvalNoiseBGV(keys.secretKey, cRes, ptm, noise, logQ);
  } else if (scheme == schemeBFV) {
    EvalNoiseBFV(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  } else {
    EvalNoiseBFVB(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  }
  Check(encvec, decvec, ptm);
  usint dcrtBits;
  if (scheme == schemeBGV)
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[1]->GetModulus().ConvertToInt()));
  else
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt()));
  Statistics(N, dcrtBits, noise, logQ, time);
}

void FullPolyDemo(usint ptm, usint coeffBound, usint k, usint logringDim, usint multDepth, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig) {
  if (multDepth == 0) {
    multDepth = (usint)ceil(log2(k)) + 1;
  }
  usint ringDim = 0;
  if(logringDim > 0) {
    ringDim = 1 << logringDim;
  }
  usint numAdd = (k/2 + 1) * coeffBound;

  CryptoContext<DCRTPoly> cc =
      scheme == schemeBGV ? GenerateContextBGV(ptm, numAdd, multDepth, ringDim, HYBRID, isTowBig)
    : GenerateContextBFV(ptm, numAdd, multDepth, 0, ringDim, HYBRID, isTowBig, 60, encMethod, multMethod);
  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  usint N = cc->GetRingDimension();
  usint size = (ptm == 2) ? 1 : N;

  std::vector<int64_t> x(size);
  for (usint i = 0; i < size; ++i) {
    x[i] = rand() % ptm;
//    x[i] = 1;
  }

  Plaintext ptxt = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(x) :
      cc->MakePackedPlaintext(x);
  Ciphertext<DCRTPoly> c = cc->Encrypt(keys.publicKey, ptxt);

  TimeVar t;
  TIC(t);

  std::vector<int64_t> coeffs(k + 1);
  for(usint i = 0; i < k + 1; ++i) {
    if(ptm == 2) {
      coeffs[i] = 1;
    } else {
      coeffs[i] = rand() % coeffBound;
    }
  }

  std::vector<Ciphertext<DCRTPoly>> cvec(k + 1);
  cvec[1] = c->Clone();
  for (usint i = 2; i < k + 1; ++i) {
    usint logi = (usint)log2(i - 1);
    cvec[i] = cc->EvalMult(cvec[1 << logi], cvec[i - (1 << logi)]);
//    if(isBGV) cvec[i] = cc->Rescale(cvec[i]);
  }

  if(ptm != 2) {
    std::vector<int64_t> constantVec(size, coeffs[1]);
    Plaintext ptxtConstMult = cc->MakePackedPlaintext(constantVec);
    cvec[1] = cc->EvalMult(cvec[1], ptxtConstMult);
  }
  std::vector<int64_t> constant(size, coeffs[0]);
  Plaintext ptxtConstant = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(constant) :
      cc->MakePackedPlaintext(constant);
  Ciphertext<DCRTPoly> cRes = cc->EvalAdd(cvec[1], ptxtConstant);
  for (usint i = 2; i <= k; ++i) {
    if(ptm != 2) {
      std::vector<int64_t> constantVecI(size, coeffs[i]);
      Plaintext ptxtConstMultI = cc->MakePackedPlaintext(constantVecI);
      cvec[i] = cc->EvalMult(cvec[i], ptxtConstMultI);
    }
    cRes = cc->EvalAdd(cRes, cvec[i]);
  }

  double time = TOC_US(t);

  std::vector<int64_t> encvec(size, 0);
  for (usint j = 0; j < size; ++j) {
    for (usint i = 0; i < k + 1; ++i) {
      int64_t powx = 1;
      int64_t cpowx;
      for (usint ii = 0; ii < i; ++ii) {
        powx *= x[j];
        powx %= ptm;
      }
      cpowx = powx;
      if(ptm != 2) cpowx *= coeffs[i];
      cpowx %= ptm;
      encvec[j] += cpowx;
      encvec[j] %= ptm;
    }
  }

  Plaintext result;
  cc->Decrypt(keys.secretKey, cRes, &result);
  std::vector<int64_t> decvec = (ptm == 2) ?
      result->GetCoefPackedValue() :
      result->GetPackedValue();

  Plaintext dRes = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(decvec) :
      cc->MakePackedPlaintext(decvec);

  double noise = 0, logQ = 0;
  if (scheme == schemeBGV) {
    EvalNoiseBGV(keys.secretKey, cRes, ptm, noise, logQ);
  } else if (scheme == schemeBFV) {
    EvalNoiseBFV(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  } else {
    EvalNoiseBFVB(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  }
  Check(encvec, decvec, ptm);
  usint dcrtBits;
  if (scheme == schemeBGV)
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[1]->GetModulus().ConvertToInt()));
  else
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt()));
  Statistics(N, dcrtBits, noise, logQ, time);
}

void EvalSumDemo(usint ptm, usint logringDim, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig) {
  usint multDepth = 1;
  usint ringDim = 1 << logringDim;
  usint numAdd = static_cast<usint>(ceil(log2(ringDim)));
  CryptoContext<DCRTPoly> cc =
      scheme == schemeBGV ? GenerateContextBGV(ptm, numAdd, multDepth, ringDim, HYBRID, isTowBig)
    : GenerateContextBFV(ptm, numAdd, multDepth, numAdd, ringDim, HYBRID, isTowBig, 60, encMethod, multMethod);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  usint N = cc->GetRingDimension();
  usint size = (ptm == 2) ? 1 : N;

  std::vector<int32_t> indexes;
  for (usint i = 1; i < size; i <<= 1) {
    indexes.push_back(static_cast<int32_t>(i));
  }
  cc->EvalAtIndexKeyGen(keys.secretKey, indexes);

  int64_t sum = 0;
  std::vector<int64_t> x(size);
  for (usint i = 0; i < size; ++i) {
    x[i] = rand() % ptm;
//    x[i] = 1;
    sum += x[i];
    sum %= ptm;
  }
  std::vector<int64_t> encvec(size, sum);
  Plaintext ptxt = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(x) :
      cc->MakePackedPlaintext(x);
  auto c = cc->Encrypt(keys.publicKey, ptxt);

  TimeVar t;
  TIC(t);

  auto cRes = c->Clone();
  for (usint i = 1; i < size; i <<= 1) {
    auto crot = cc->EvalAtIndex(cRes, i);
    cRes = cc->EvalAdd(cRes, crot);
  }
  double time = TOC_US(t);

  Plaintext result;
  cc->Decrypt(keys.secretKey, cRes, &result);
  std::vector<int64_t> decvec = (ptm == 2) ?
      result->GetCoefPackedValue() :
      result->GetPackedValue();
  Plaintext dRes = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(decvec) :
      cc->MakePackedPlaintext(decvec);
  double noise = 0, logQ = 0;
  if (scheme == schemeBGV) {
    EvalNoiseBGV(keys.secretKey, cRes, ptm, noise, logQ);
  } else if (scheme == schemeBFV) {
    EvalNoiseBFV(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  } else {
    EvalNoiseBFVB(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  }
  Check(encvec, decvec, ptm);
  usint dcrtBits;
  if (scheme == schemeBGV)
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[1]->GetModulus().ConvertToInt()));
  else
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt()));
  Statistics(N, dcrtBits, noise, logQ, time);
}

void HorzInnerProdDemo(usint ptm, usint logringDim, EncryptionTechnique encMethod, MultiplicationTechnique multMethod, usint scheme, bool isTowBig) {
  usint multDepth = 1;
  usint ringDim = 1 << logringDim;
  usint numAdd = static_cast<usint>(ceil(log2(ringDim)));
  CryptoContext<DCRTPoly> cc =
      scheme == schemeBGV ? GenerateContextBGV(ptm, numAdd, multDepth, ringDim, HYBRID, isTowBig)
    : GenerateContextBFV(ptm, numAdd, multDepth, numAdd, ringDim, HYBRID, isTowBig, 37, encMethod, multMethod);

  auto keys = cc->KeyGen();
  cc->EvalMultKeyGen(keys.secretKey);

  usint N = cc->GetRingDimension();
  usint size = (ptm == 2) ? 1 : N;

  std::vector<int32_t> indexes;
  for (usint i = 1; i < size; i <<= 1) {
    indexes.push_back(static_cast<int32_t>(i));
  }
  cc->EvalAtIndexKeyGen(keys.secretKey, indexes);

  int64_t ip = 0;
  std::vector<int64_t> x(size);
  std::vector<int64_t> y(size);
  for (usint i = 0; i < size; ++i) {
    x[i] = rand() % ptm;
    y[i] = rand() % ptm;
//    x[i] = 1;
    ip += x[i] * y[i];
    ip %= ptm;
  }
  std::vector<int64_t> encvec(size, ip);
  Plaintext ptxtx = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(x) :
      cc->MakePackedPlaintext(x);
  Plaintext ptxty = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(y) :
      cc->MakePackedPlaintext(y);

  auto cx = cc->Encrypt(keys.publicKey, ptxtx);
  auto cy = cc->Encrypt(keys.publicKey, ptxty);

  TimeVar t;
  TIC(t);

  auto cRes = cc->EvalMult(cx, cy);
//  if(isBGV) cRes = cc->Rescale(cRes);

  for (usint i = 1; i < size; i <<= 1) {
    auto crot = cc->EvalAtIndex(cRes, i);
    cRes = cc->EvalAdd(cRes, crot);
  }
  double time = TOC_US(t);

  Plaintext result;
  cc->Decrypt(keys.secretKey, cRes, &result);
  std::vector<int64_t> decvec = (ptm == 2) ?
      result->GetCoefPackedValue() :
      result->GetPackedValue();
  Plaintext dRes = (ptm == 2) ?
      cc->MakeCoefPackedPlaintext(decvec) :
      cc->MakePackedPlaintext(decvec);
  double noise = 0, logQ = 0;
  if (scheme == schemeBGV) {
    EvalNoiseBGV(keys.secretKey, cRes, ptm, noise, logQ);
  } else if (scheme == schemeBFV) {
    EvalNoiseBFV(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  } else {
    EvalNoiseBFVB(keys.secretKey, cRes, dRes, ptm, noise, logQ, encMethod);
  }
  Check(encvec, decvec, ptm);
  usint dcrtBits;
  if (scheme == schemeBGV)
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[1]->GetModulus().ConvertToInt()));
  else
    dcrtBits = round(log2(cc->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt()));
  Statistics(N, dcrtBits, noise, logQ, time);
}

void Check(std::vector<int64_t> encvec, std::vector<int64_t> decvec, usint ptm) {
  for (usint i = 0; i < encvec.size(); ++i) {
    while(encvec[i] < 0) {
      encvec[i] += ptm;
    }
    while(decvec[i] < 0) {
      decvec[i] += ptm;
    }
    if(encvec[i] != decvec[i]) {
      std::cerr << "ERROR!!!: " << i << ", " << encvec[i] << ", " << decvec[i] << std::endl;
      break;
    }
  }
}

void Head() {
 std::cerr << "$k$ & $\\log N$ & $\\log q_i$ & $\\log Q$ & $\\log e$ & time & $\\log N$ & $\\log q_i$ & $\\log Q$ & $\\log e$ & time & $\\log N$ & $\\log q_i$ & $\\log Q$ & $\\log e$ & time & $\\log N$ & $\\log q_i$ & $\\log Q$ & $\\log e$ & time " << std::endl;
}

void Statistics(usint N, usint dcrtBits, double noise, double logQ, double time) {
  std::cerr << " & " << log2(N) << " & " << dcrtBits << " & ";
  std::cerr << round(logQ) << " & " << round(noise) << " & ";
//  std::cerr << round(time / 10000) / 100 << " s";

  if (time < 100000) {
    std::cerr << round(time/1000) / 1000 << " s\n";
  } else {
    std::cerr << round(time / 10000) / 100 << " s\n";
  }
}

void EvalNoiseBGV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, usint ptm, double& noise, double& logQ) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBGVRNS>(
          ciphertext->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  PrivateKey<DCRTPoly> sk(privateKey);
  const DCRTPoly &s = privateKey->GetPrivateElement();

  size_t sizeQl = cv[0].GetParams()->GetParams().size();
  size_t sizeQ = s.GetParams()->GetParams().size();

  size_t diffQl = sizeQ - sizeQl;

  auto scopy(s);
  scopy.DropLastElements(diffQl);

  DCRTPoly sPower(scopy);

  DCRTPoly b, ci;

  if (cv[0].GetFormat() == Format::EVALUATION) {
    b = cv[0];
    for (size_t i = 1; i < cv.size(); i++) {
      ci = cv[i];
      ci.SetFormat(Format::EVALUATION);

      b += sPower * ci;
      sPower *= scopy;
    }
    b.SetFormat(Format::COEFFICIENT);
  }

  noise = (log2(b.Norm())-log2(ptm));
  logQ = 0;
  for (usint i = 0; i < sizeQ - 1; i++) {
    double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
    logQ += logqi;
  }
  for (usint i = sizeQl; i < sizeQ - 1; i++) {
    double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
    noise += logqi;
  }
}

void EvalNoiseBFV(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm, double& noise, double& logQ, EncryptionTechnique encMethod) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          privateKey->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  DCRTPoly s = privateKey->GetPrivateElement();
  if (encMethod == POVERQ)
    s.DropLastElement();
  DCRTPoly sPower(s);

  DCRTPoly b = cv[0];
  b.SetFormat(Format::EVALUATION);

  DCRTPoly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= s;
  }

  DCRTPoly res;
  Poly bigPtxt = ptxt->GetElement<DCRTPoly>().CRTInterpolate();
  bigPtxt = bigPtxt.MultiplyAndRound(bigPtxt.GetModulus(),cryptoParams->GetPlaintextModulus());
  DCRTPoly plain(bigPtxt,ptxt->GetElement<DCRTPoly>().GetParams());
  plain.SetFormat(Format::EVALUATION);
  res = b - plain;

  // Converts back to coefficient representation
  res.SetFormat(Format::COEFFICIENT);
  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
  noise = (log2(res.Norm()));

  logQ = 0;
  for (usint i = 0; i < sizeQ; i++) {
    double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
    logQ += logqi;
  }
}

void EvalNoiseBFVB(PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, Plaintext ptxt, usint ptm, double& noise, double& logQ, EncryptionTechnique encMethod) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          privateKey->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  const DCRTPoly &s = privateKey->GetPrivateElement();
  DCRTPoly sPower(s);

  DCRTPoly b = cv[0];
  b.SetFormat(Format::EVALUATION);

  DCRTPoly ci;
  for (size_t i = 1; i < cv.size(); i++) {
    ci = cv[i];
    ci.SetFormat(Format::EVALUATION);

    b += sPower * ci;
    sPower *= s;
  }

  DCRTPoly res;
  
  Poly bigPtxt = ptxt->GetElement<DCRTPoly>().CRTInterpolate();
  bigPtxt = bigPtxt.MultiplyAndRound(bigPtxt.GetModulus(),cryptoParams->GetPlaintextModulus());
  DCRTPoly plain(bigPtxt,ptxt->GetElement<DCRTPoly>().GetParams());
  plain.SetFormat(Format::EVALUATION);
  res = b - plain;

  // Converts back to coefficient representation
  res.SetFormat(Format::COEFFICIENT);
  size_t sizeQ = s.GetParams()->GetParams().size();
  noise = (log2(res.Norm()));

  logQ = 0;
  for (usint i = 0; i < sizeQ; i++) {
    double logqi = log2(cryptoParams->GetElementParams()->GetParams()[i]->GetModulus().ConvertToInt());
    logQ += logqi;
  }
}

