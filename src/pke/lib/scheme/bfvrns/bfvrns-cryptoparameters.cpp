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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"

namespace lbcrypto {

// Precomputation of CRT tables for encryption, decryption, and homomorphic multiplication
void CryptoParametersBFVRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech,
                                                 EncryptionTechnique encTech, MultiplicationTechnique multTech,
                                                 uint32_t numPartQ, uint32_t auxBits, uint32_t extraBits) {
    CryptoParametersRNS::PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, extraBits);

    NativeInteger t     = GetPlaintextModulus();
    uint32_t n          = GetElementParams()->GetRingDimension();
    BigInteger modulusQ = GetElementParams()->GetModulus();
    const auto& paramsQ = GetElementParams()->GetParams();
    size_t sizeQ        = paramsQ.size();

    m_modqBarrettMu.resize(0);
    m_modqBarrettMu.reserve(sizeQ);
    m_tInvModq.resize(0);
    m_tInvModq.reserve(sizeQ);

    std::vector<NativeInteger> moduliQ, rootsQ;
    moduliQ.reserve(sizeQ);
    rootsQ.reserve(sizeQ);

    const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
    for (const auto& p : paramsQ) {
        m_tInvModq.emplace_back(t.ModInverse(p->GetModulus()));
        m_modqBarrettMu.emplace_back((BarrettBase128Bit / BigInteger(p->GetModulus())).ConvertToInt<DoubleNativeInt>());
        moduliQ.emplace_back(p->GetModulus());
        rootsQ.emplace_back(p->GetRootOfUnity());
    }

    /////////////////////////////////////
    // BFVrns : Encrypt
    /////////////////////////////////////

    NativeInteger modulusr = PreviousPrime<NativeInteger>(moduliQ[sizeQ - 1], 2 * n);
    NativeInteger rootr    = RootOfUnity<NativeInteger>(2 * n, modulusr);

    BigInteger tmpModulusQ = modulusQ;

    m_negQModt.clear();
    m_negQModtPrecon.clear();
    m_negQModt.resize(sizeQ);
    m_negQModtPrecon.resize(sizeQ);
    for (size_t l = 0; l < sizeQ; l++) {
        if (l > 0)
            tmpModulusQ = tmpModulusQ / BigInteger(moduliQ[sizeQ - l]);

        m_negQModt[l]       = tmpModulusQ.Mod(BigInteger(GetPlaintextModulus())).ConvertToInt();
        m_negQModt[l]       = t.Sub(m_negQModt[l]);
        m_negQModtPrecon[l] = m_negQModt[l].PrepModMulConst(t);
    }

    // BFVrns : Encrypt : With extra
    if (encTech == EXTENDED) {
        std::vector<NativeInteger> moduliQr(sizeQ + 1);
        std::vector<NativeInteger> rootsQr(sizeQ + 1);

        m_rInvModq.resize(sizeQ);

        m_tInvModqr.resize(sizeQ + 1);

        for (uint32_t i = 0; i < sizeQ; i++) {
            moduliQr[i] = moduliQ[i];
            rootsQr[i]  = rootsQ[i];

            m_tInvModqr[i] = m_tInvModq[i];
            m_rInvModq[i]  = modulusr.ModInverse(moduliQ[i]);
        }
        moduliQr[sizeQ] = modulusr;
        rootsQr[sizeQ]  = rootr;
        m_paramsQr      = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQr, rootsQr);

        m_tInvModqr[sizeQ] = t.ModInverse(modulusr);

        BigInteger modulusQr = modulusQ.Mul(modulusr);
        m_negQrModt          = modulusQr.Mod(BigInteger(t)).ConvertToInt();
        m_negQrModt          = t.Sub(m_negQrModt);
        m_negQrModtPrecon    = m_negQrModt.PrepModMulConst(t);
    }

    /////////////////////////////////////
    // HPS Precomputation
    /////////////////////////////////////

    if (multTech != BEHZ) {
        size_t sizeR = (multTech == HPS) ? sizeQ + 1 : sizeQ;
        std::vector<NativeInteger> moduliR(sizeR);
        std::vector<NativeInteger> rootsR(sizeR);
        m_modrBarrettMu.resize(sizeR);

        moduliR[0]         = modulusr;
        rootsR[0]          = rootr;
        m_modrBarrettMu[0] = (BarrettBase128Bit / BigInteger(moduliR[0])).ConvertToInt<DoubleNativeInt>();

        for (size_t j = 1; j < sizeR; j++) {
            moduliR[j]         = PreviousPrime<NativeInteger>(moduliR[j - 1], 2 * n);
            rootsR[j]          = RootOfUnity<NativeInteger>(2 * n, moduliR[j]);
            m_modrBarrettMu[j] = (BarrettBase128Bit / BigInteger(moduliR[j])).ConvertToInt<DoubleNativeInt>();
        }

        ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsR, 2 * n, moduliR);

        // BFVrns : Mult : ExpandCRTBasis
        // Pre-compute values [Ql/q_i]_{r_j}
        // Pre-compute values [(Ql/q_i)^{-1}]_{q_i}

        tmpModulusQ = modulusQ;

        if (multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ) {
            m_QlHatInvModq.resize(sizeQ);
            m_QlHatInvModqPrecon.resize(sizeQ);
            m_QlHatModr.resize(sizeQ);

            for (size_t l = 0; l < sizeQ; l++) {
                if (l > 0)
                    tmpModulusQ = tmpModulusQ / BigInteger(moduliQ[sizeQ - l]);

                m_QlHatInvModq[sizeQ - l - 1].resize(sizeQ - l);
                m_QlHatInvModqPrecon[sizeQ - l - 1].resize(sizeQ - l);
                m_QlHatModr[sizeQ - l - 1].resize(sizeR);

                for (size_t j = 0; j < sizeR; j++) {
                    m_QlHatModr[sizeQ - l - 1][j].resize(sizeQ - l);
                }

                for (size_t i = 0; i < sizeQ - l; i++) {
                    m_QlHatModr[sizeQ - l - 1][i].resize(sizeR);
                    BigInteger QHati                 = tmpModulusQ / BigInteger(moduliQ[i]);
                    BigInteger QHatInvModqi          = QHati.ModInverse(moduliQ[i]);
                    m_QlHatInvModq[sizeQ - l - 1][i] = QHatInvModqi.ConvertToInt();
                    m_QlHatInvModqPrecon[sizeQ - l - 1][i] =
                        m_QlHatInvModq[sizeQ - l - 1][i].PrepModMulConst(moduliQ[i]);
                    for (size_t j = 0; j < sizeR; j++) {
                        BigInteger QlHatModrij           = QHati.Mod(moduliR[j]);
                        m_QlHatModr[sizeQ - l - 1][j][i] = QlHatModrij.ConvertToInt();
                    }
                }
            }
        }
        else {
            m_QlHatInvModq.resize(1);
            m_QlHatInvModqPrecon.resize(1);

            m_QlHatInvModq[0].resize(sizeQ);
            m_QlHatInvModqPrecon[0].resize(sizeQ);

            for (size_t i = 0; i < sizeQ; i++) {
                BigInteger QHati           = modulusQ / BigInteger(moduliQ[i]);
                BigInteger QHatInvModqi    = QHati.ModInverse(moduliQ[i]);
                m_QlHatInvModq[0][i]       = QHatInvModqi.ConvertToInt();
                m_QlHatInvModqPrecon[0][i] = m_QlHatInvModq[0][i].PrepModMulConst(moduliQ[i]);
            }

            m_QlHatModr.resize(1);
            m_QlHatModr[0].resize(sizeR);
            for (usint j = 0; j < sizeR; j++) {
                m_QlHatModr[0][j].resize(sizeQ);
                for (usint i = 0; i < sizeQ; i++) {
                    BigInteger QHati     = modulusQ / BigInteger(moduliQ[i]);
                    m_QlHatModr[0][j][i] = QHati.Mod(moduliR[j]).ConvertToInt();
                }
            }
        }

        // BFVrns : Mult : ExpandCRTBasis
        if (multTech == HPS) {
            m_paramsQl.resize(1);
            m_paramsRl.resize(1);
            m_paramsQlRl.resize(1);
            m_paramsQl[0] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQ, rootsQ);
            m_paramsRl[0] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliR, rootsR);
            std::vector<NativeInteger> moduliQR(sizeQ + sizeR);
            std::vector<NativeInteger> rootsQR(sizeQ + sizeR);
            for (size_t i = 0; i < sizeQ; i++) {
                moduliQR[i] = moduliQ[i];
                rootsQR[i]  = rootsQ[i];
            }
            for (size_t j = 0; j < sizeR; j++) {
                moduliQR[sizeQ + j] = moduliR[j];
                rootsQR[sizeQ + j]  = rootsR[j];
            }
            m_paramsQlRl[0] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQR, rootsQR);
        }
        else if (multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ) {
            m_paramsQl.resize(sizeQ);
            m_paramsRl.resize(sizeQ);
            m_paramsQlRl.resize(sizeQ);

            std::vector<NativeInteger> moduliQl;
            moduliQl.reserve(sizeQ);
            std::vector<NativeInteger> rootsQl;
            rootsQl.reserve(sizeQ);
            std::vector<NativeInteger> moduliRl;
            moduliRl.reserve(sizeQ);
            std::vector<NativeInteger> rootsRl;
            rootsRl.reserve(sizeQ);
            std::vector<NativeInteger> moduliQlRl;
            moduliQlRl.reserve(2 * sizeQ);
            std::vector<NativeInteger> rootsQlRl;
            rootsQlRl.reserve(2 * sizeQ);

            for (usint l = 0; l < sizeQ; ++l) {
                moduliQl.push_back(moduliQ[l]);
                rootsQl.push_back(rootsQ[l]);
                m_paramsQl[l] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQl, rootsQl);
                moduliRl.push_back(moduliR[l]);
                rootsRl.push_back(rootsR[l]);
                m_paramsRl[l] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliRl, rootsRl);
                moduliQlRl.insert(moduliQlRl.begin() + l, moduliQ[l]);
                rootsQlRl.insert(rootsQlRl.begin() + l, rootsQ[l]);
                moduliQlRl.push_back(moduliR[l]);
                rootsQlRl.push_back(rootsR[l]);
                m_paramsQlRl[l] = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQlRl, rootsQlRl);
            }
        }

        m_modrBarrettMu.resize(sizeR);
        for (uint32_t j = 0; j < moduliR.size(); j++) {
            m_modrBarrettMu[j] = (BarrettBase128Bit / BigInteger(moduliR[j])).ConvertToInt<DoubleNativeInt>();
        }

        m_qInv.resize(sizeQ);
        for (size_t i = 0; i < sizeQ; i++) {
            m_qInv[i] = 1. / static_cast<double>(moduliQ[i].ConvertToInt());
        }

        /////////////////////////////////////
        // BFVrns : Mult : ScaleAndRound
        /////////////////////////////////////

        const BigInteger modulusR = multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ ?
                                        m_paramsRl[sizeQ - 1]->GetModulus() :
                                        m_paramsRl[0]->GetModulus();

        const BigInteger modulusQR = multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ ?
                                         m_paramsQlRl[sizeQ - 1]->GetModulus() :
                                         m_paramsQlRl[0]->GetModulus();

        const BigInteger modulust(GetPlaintextModulus());

        m_tRSHatInvModsDivsFrac.resize(sizeQ);
        for (size_t i = 0; i < sizeQ; i++) {
            BigInteger qi(moduliQ[i].ConvertToInt());
            m_tRSHatInvModsDivsFrac[i] =
                static_cast<double>(
                    ((modulusQR.DividedBy(qi)).ModInverse(qi) * modulusR * modulust).Mod(qi).ConvertToInt()) /
                static_cast<double>(qi.ConvertToInt());
        }

        m_tRSHatInvModsDivsModr.resize(sizeR);
        for (usint j = 0; j < sizeR; j++) {
            m_tRSHatInvModsDivsModr[j].reserve(sizeQ + 1);
            BigInteger rj(moduliR[j].ConvertToInt());
            for (usint i = 0; i < sizeQ; i++) {
                BigInteger qi(moduliQ[i].ConvertToInt());
                BigInteger tRSHatInvMods     = modulust * modulusR * ((modulusQR.DividedBy(qi)).ModInverse(qi));
                BigInteger tRSHatInvModsDivs = tRSHatInvMods / qi;
                m_tRSHatInvModsDivsModr[j].push_back(tRSHatInvModsDivs.Mod(rj).ConvertToInt());
            }

            BigInteger tRSHatInvMods     = modulust * modulusR * ((modulusQR.DividedBy(rj)).ModInverse(rj));
            BigInteger tRSHatInvModsDivs = tRSHatInvMods / rj;
            m_tRSHatInvModsDivsModr[j].push_back(tRSHatInvModsDivs.Mod(rj).ConvertToInt());
        }

        /////////////////////////////////////
        // BFVrns : Mult : SwitchCRTBasis
        /////////////////////////////////////

        std::vector<BigInteger> Ql(sizeQ + 1);
        std::vector<BigInteger> Rl(sizeQ + 1);
        std::vector<BigInteger> QlRl(sizeQ + 1);
        std::vector<BigInteger> QlHat(sizeQ + 1);
        std::vector<BigInteger> RlHat(sizeQ + 1);

        if (multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ) {
            Ql[0]    = 1;
            Rl[0]    = 1;
            QlRl[0]  = 1;
            QlHat[0] = modulusQ;
            RlHat[0] = modulusR;
            for (usint l = 0; l < sizeQ; ++l) {
                BigInteger ql(moduliQ[l].ConvertToInt());
                BigInteger rl(moduliR[l].ConvertToInt());
                Ql[l + 1]    = Ql[l] * ql;
                Rl[l + 1]    = Rl[l] * rl;
                QlRl[l + 1]  = QlRl[l] * ql;
                QlRl[l + 1]  = QlRl[l + 1] * rl;
                QlHat[l + 1] = QlHat[l] / ql;
                RlHat[l + 1] = RlHat[l] / rl;
            }
        }

        // BFVrns : Mult : ExpandCRTBasis
        if (multTech == HPS) {
            m_alphaQlModr.resize(1);
            m_alphaQlModr[0].resize(sizeQ + 1, std::vector<NativeInteger>(sizeR));
            for (usint j = 0; j < sizeR; j++) {
                NativeInteger QModrj = modulusQ.Mod(moduliR[j]).ConvertToInt();
                for (usint i = 0; i < sizeQ + 1; i++) {
                    m_alphaQlModr[0][i][j] = QModrj.ModMul(NativeInteger(i), moduliR[j]);
                }
            }
        }
        else if (multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ) {
            m_alphaQlModr.resize(sizeQ);
            for (usint l = sizeQ; l > 0; l--) {
                m_alphaQlModr[l - 1].resize(l + 1, std::vector<NativeInteger>(sizeR));
                for (usint i = 0; i < sizeR; i++) {
                    NativeInteger QlModri = Ql[l].Mod(moduliR[i]).ConvertToInt();
                    for (usint j = 0; j < l + 1; ++j) {
                        m_alphaQlModr[l - 1][j][i] = QlModri.ModMul(NativeInteger(j), moduliR[i]);
                    }
                }
            }
        }

        // Pre-compute values [Rl/r_j]_{q_i}
        // Pre-compute values [(Rl/r_j)^{-1}]_{r_j}
        if (multTech == HPS) {
            m_RlHatInvModr.resize(1);
            m_RlHatInvModrPrecon.resize(1);

            m_RlHatInvModr[0].resize(sizeR);
            m_RlHatInvModrPrecon[0].resize(sizeR);
            for (size_t j = 0; j < sizeR; j++) {
                BigInteger RHatj           = modulusR / BigInteger(moduliR[j]);
                m_RlHatInvModr[0][j]       = RHatj.ModInverse(moduliR[j]).ConvertToInt();
                m_RlHatInvModrPrecon[0][j] = m_RlHatInvModr[0][j].PrepModMulConst(moduliR[j]);
            }

            m_RlHatModq.resize(1);
            m_RlHatModq[0].resize(sizeQ);
            for (usint i = 0; i < sizeQ; i++) {
                m_RlHatModq[0][i].resize(sizeR);
                for (usint j = 0; j < sizeR; j++) {
                    BigInteger RHatj     = modulusR / BigInteger(moduliR[j]);
                    m_RlHatModq[0][i][j] = RHatj.Mod(moduliQ[i]).ConvertToInt();
                }
            }
        }
        else if (multTech == HPSPOVERQ || multTech == HPSPOVERQLEVELED) {
            m_RlHatInvModr.resize(sizeR);
            m_RlHatInvModrPrecon.resize(sizeR);
            m_RlHatModq.resize(sizeR);

            for (usint l = sizeR; l > 0; l--) {
                m_RlHatInvModr[l - 1].resize(l);
                m_RlHatInvModrPrecon[l - 1].resize(l);
                m_RlHatModq[l - 1].resize(l, std::vector<NativeInteger>(l));
                for (size_t j = 0; j < l; j++) {
                    BigInteger RlHatj              = Rl[l] / BigInteger(moduliR[j]);
                    BigInteger RlHatInvModrj       = RlHatj.ModInverse(moduliR[j]);
                    m_RlHatInvModr[l - 1][j]       = RlHatInvModrj.ConvertToInt();
                    m_RlHatInvModrPrecon[l - 1][j] = m_RlHatInvModr[l - 1][j].PrepModMulConst(moduliR[j]);
                    for (size_t i = 0; i < l; i++) {
                        BigInteger RlHatModqji   = RlHatj.Mod(moduliQ[i]);
                        m_RlHatModq[l - 1][i][j] = RlHatModqji.ConvertToInt();
                    }
                }
            }
        }

        // compute [\alpha*Rl]_{q_i} for 0 <= alpha <= sizeRl
        // used for homomorphic multiplication
        if (multTech == HPS) {
            m_alphaRlModq.resize(1);
            m_alphaRlModq[0].resize(sizeR + 1, std::vector<NativeInteger>(sizeQ));
            for (usint i = 0; i < sizeQ; i++) {
                NativeInteger RModqi = modulusR.Mod(moduliQ[i]).ConvertToInt();
                for (usint j = 0; j < sizeR + 1; ++j) {
                    m_alphaRlModq[0][j][i] = RModqi.ModMul(NativeInteger(j), moduliQ[i]);
                }
            }
        }
        else if (multTech == HPSPOVERQLEVELED || multTech == HPSPOVERQ) {
            m_alphaRlModq.resize(sizeR);
            for (usint l = sizeR; l > 0; l--) {
                m_alphaRlModq[l - 1].resize(l + 1, std::vector<NativeInteger>(sizeQ));
                for (usint i = 0; i < sizeQ; i++) {
                    NativeInteger RlModqi = Rl[l].Mod(moduliQ[i]).ConvertToInt();
                    for (usint j = 0; j < l + 1; ++j) {
                        m_alphaRlModq[l - 1][j][i] = RlModqi.ModMul(NativeInteger(j), moduliQ[i]);
                    }
                }
            }
        }

        m_rInv.resize(sizeR);
        for (size_t j = 0; j < sizeR; j++) {
            m_rInv[j] = 1. / static_cast<double>(moduliR[j].ConvertToInt());
        }

        /////////////////////////////////////
        // BFVrns : Decrypt : ScaleAndRound
        /////////////////////////////////////

        usint qMSB     = moduliQ[0].GetMSB();
        usint sizeQMSB = GetMSB64(sizeQ);

        m_tQHatInvModqDivqModt.resize(sizeQ);
        m_tQHatInvModqDivqModtPrecon.resize(sizeQ);
        m_tQHatInvModqDivqFrac.resize(sizeQ);
        if (qMSB + sizeQMSB < 52) {
            for (size_t i = 0; i < sizeQ; i++) {
                BigInteger qi(moduliQ[i].ConvertToInt());
                BigInteger tQHatInvModqi =
                    ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus()));
                BigInteger tQHatInvModqDivqi    = tQHatInvModqi.DividedBy(qi);
                m_tQHatInvModqDivqModt[i]       = tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
                m_tQHatInvModqDivqModtPrecon[i] = m_tQHatInvModqDivqModt[i].PrepModMulConst(GetPlaintextModulus());

                int64_t numerator         = tQHatInvModqi.Mod(qi).ConvertToInt();
                int64_t denominator       = moduliQ[i].ConvertToInt();
                m_tQHatInvModqDivqFrac[i] = static_cast<double>(numerator) / static_cast<double>(denominator);
            }
        }
        else {
            m_tQHatInvModqBDivqModt.resize(sizeQ);
            m_tQHatInvModqBDivqModtPrecon.resize(sizeQ);
            m_tQHatInvModqBDivqFrac.resize(sizeQ);
            usint qMSBHf = qMSB >> 1;
            for (size_t i = 0; i < sizeQ; i++) {
                BigInteger qi(moduliQ[i].ConvertToInt());
                BigInteger tQHatInvModqi =
                    ((modulusQ.DividedBy(qi)).ModInverse(qi) * BigInteger(GetPlaintextModulus()));
                BigInteger tQHatInvModqDivqi    = tQHatInvModqi.DividedBy(qi);
                m_tQHatInvModqDivqModt[i]       = tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
                m_tQHatInvModqDivqModtPrecon[i] = m_tQHatInvModqDivqModt[i].PrepModMulConst(GetPlaintextModulus());

                int64_t numerator         = tQHatInvModqi.Mod(qi).ConvertToInt();
                int64_t denominator       = moduliQ[i].ConvertToInt();
                m_tQHatInvModqDivqFrac[i] = static_cast<double>(numerator) / static_cast<double>(denominator);

                tQHatInvModqi.LShiftEq(qMSBHf);
                tQHatInvModqDivqi                = tQHatInvModqi.DividedBy(qi);
                m_tQHatInvModqBDivqModt[i]       = tQHatInvModqDivqi.Mod(GetPlaintextModulus()).ConvertToInt();
                m_tQHatInvModqBDivqModtPrecon[i] = m_tQHatInvModqBDivqModt[i].PrepModMulConst(GetPlaintextModulus());

                numerator                  = tQHatInvModqi.Mod(qi).ConvertToInt();
                m_tQHatInvModqBDivqFrac[i] = static_cast<double>(numerator) / static_cast<double>(denominator);
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : FastExpandCRTBasisPloverQ
        /////////////////////////////////////

        if (multTech == HPSPOVERQ || multTech == HPSPOVERQLEVELED) {
            // Scenario when we go from Q to P_l
            m_negRlQHatInvModq.resize(sizeR);
            m_negRlQHatInvModqPrecon.resize(sizeR);
            for (usint l = sizeR; l > 0; l--) {
                m_negRlQHatInvModq[l - 1].resize(sizeQ);
                m_negRlQHatInvModqPrecon[l - 1].resize(sizeQ);
                for (usint i = 0; i < sizeQ; i++) {
                    BigInteger QHati                   = modulusQ / BigInteger(moduliQ[i]);
                    BigInteger QHatInvModqi            = QHati.ModInverse(moduliQ[i]);
                    m_negRlQHatInvModq[l - 1][i]       = Rl[l].ModMul(QHatInvModqi, moduliQ[i]).ConvertToInt();
                    m_negRlQHatInvModq[l - 1][i]       = moduliQ[i].Sub(m_negRlQHatInvModq[l - 1][i]);
                    m_negRlQHatInvModqPrecon[l - 1][i] = m_negRlQHatInvModq[l - 1][i].PrepModMulConst(moduliQ[i]);
                }
            }

            // Scenario when we go from Q_l to P_l
            m_negRlQlHatInvModq.resize(sizeR);
            m_negRlQlHatInvModqPrecon.resize(sizeR);
            BigInteger modulusQtmp = modulusQ;
            for (usint l = sizeR; l > 0; l--) {
                m_negRlQlHatInvModq[l - 1].resize(l);
                m_negRlQlHatInvModqPrecon[l - 1].resize(l);
                for (usint i = 0; i < l; i++) {
                    BigInteger QlHati                   = modulusQtmp / BigInteger(moduliQ[i]);
                    BigInteger QlHatInvModqi            = QlHati.ModInverse(moduliQ[i]);
                    m_negRlQlHatInvModq[l - 1][i]       = Rl[l].ModMul(QlHatInvModqi, moduliQ[i]).ConvertToInt();
                    m_negRlQlHatInvModq[l - 1][i]       = moduliQ[i].Sub(m_negRlQlHatInvModq[l - 1][i]);
                    m_negRlQlHatInvModqPrecon[l - 1][i] = m_negRlQlHatInvModq[l - 1][i].PrepModMulConst(moduliQ[i]);
                }
                modulusQtmp = modulusQtmp / BigInteger(moduliQ[l - 1]);
            }
        }

        m_qInvModr.resize(sizeQ);
        for (usint i = 0; i < sizeQ; i++) {
            m_qInvModr[i].resize(sizeR);
            for (usint j = 0; j < sizeR; j++) {
                m_qInvModr[i][j] = moduliQ[i].ModInverse(moduliR[j]);
            }
        }

        modulusQ = GetElementParams()->GetModulus();

        /////////////////////////////////////
        // BFVrns : Mult : ScaleAndRoundP
        /////////////////////////////////////

        if (multTech == HPS) {
            m_tQlSlHatInvModsDivsFrac.resize(1);

            m_tQlSlHatInvModsDivsFrac[0].resize(sizeR);
            for (size_t j = 0; j < sizeR; j++) {
                BigInteger rj(moduliR[j].ConvertToInt());
                m_tQlSlHatInvModsDivsFrac[0][j] =
                    static_cast<double>(
                        ((modulusQR.DividedBy(rj)).ModInverse(rj) * modulusQ * modulust).Mod(rj).ConvertToInt()) /
                    static_cast<double>(rj.ConvertToInt());
            }
            m_tQlSlHatInvModsDivsModq.resize(1);
            m_tQlSlHatInvModsDivsModq[0].resize(sizeQ, std::vector<NativeInteger>(sizeR + 1));
            for (usint i = 0; i < sizeQ; i++) {
                BigInteger qi(moduliQ[i].ConvertToInt());
                for (usint j = 0; j < sizeR; j++) {
                    BigInteger rj(moduliR[j].ConvertToInt());
                    BigInteger tQlSlHatInvMods     = modulust * modulusQ * ((modulusQR.DividedBy(rj)).ModInverse(rj));
                    BigInteger tQlSlHatInvModsDivs = tQlSlHatInvMods / rj;
                    m_tQlSlHatInvModsDivsModq[0][i][j] = tQlSlHatInvModsDivs.Mod(qi).ConvertToInt();
                }

                BigInteger tQlSlHatInvMods     = modulust * modulusQ * ((modulusQR.DividedBy(qi)).ModInverse(qi));
                BigInteger tQlSlHatInvModsDivs = tQlSlHatInvMods / qi;
                m_tQlSlHatInvModsDivsModq[0][i][sizeR] = tQlSlHatInvModsDivs.Mod(qi).ConvertToInt();
            }
        }
        else if ((multTech == HPSPOVERQ) || (multTech == HPSPOVERQLEVELED)) {
            m_tQlSlHatInvModsDivsFrac.resize(sizeQ);
            m_tQlSlHatInvModsDivsModq.resize(sizeQ);

            for (usint l = sizeQ; l > 0; l--) {
                m_tQlSlHatInvModsDivsFrac[l - 1].resize(l);
                for (size_t j = 0; j < l; j++) {
                    BigInteger rj(moduliR[j].ConvertToInt());
                    m_tQlSlHatInvModsDivsFrac[l - 1][j] =
                        static_cast<double>(
                            ((QlRl[l].DividedBy(rj)).ModInverse(rj) * Ql[l] * modulust).Mod(rj).ConvertToInt()) /
                        static_cast<double>(rj.ConvertToInt());
                }
                m_tQlSlHatInvModsDivsModq[l - 1].resize(l, std::vector<NativeInteger>(l + 1));
                for (usint i = 0; i < l; i++) {
                    BigInteger qi(moduliQ[i].ConvertToInt());
                    for (usint j = 0; j < l; j++) {
                        BigInteger rj(moduliR[j].ConvertToInt());
                        BigInteger tQlSlHatInvMods     = modulust * Ql[l] * ((QlRl[l].DividedBy(rj)).ModInverse(rj));
                        BigInteger tQlSlHatInvModsDivs = tQlSlHatInvMods / rj;
                        m_tQlSlHatInvModsDivsModq[l - 1][i][j] = tQlSlHatInvModsDivs.Mod(qi).ConvertToInt();
                    }

                    BigInteger tQlSlHatInvMods     = modulust * Ql[l] * ((QlRl[l].DividedBy(qi)).ModInverse(qi));
                    BigInteger tQlSlHatInvModsDivs = tQlSlHatInvMods / qi;
                    m_tQlSlHatInvModsDivsModq[l - 1][i][l] = tQlSlHatInvModsDivs.Mod(qi).ConvertToInt();
                }
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : ScaleAndRoundQl
        /////////////////////////////////////

        m_QlQHatInvModqDivqModq.resize(sizeQ);
        m_QlQHatInvModqDivqFrac.resize(sizeQ);
        for (usint l = sizeQ; l > 0; l--) {
            m_QlQHatInvModqDivqFrac[l - 1].resize(sizeQ - l);
            for (size_t j = 0; j < sizeQ - l; j++) {
                BigInteger qj(moduliQ[j + l].ConvertToInt());
                m_QlQHatInvModqDivqFrac[l - 1][j] =
                    static_cast<double>(((modulusQ.DividedBy(qj)).ModInverse(qj) * Ql[l]).Mod(qj).ConvertToInt()) /
                    static_cast<double>(qj.ConvertToInt());
            }
            m_QlQHatInvModqDivqModq[l - 1].resize(l);
            for (usint i = 0; i < l; i++) {
                m_QlQHatInvModqDivqModq[l - 1][i].resize(sizeQ - l + 1);
                BigInteger qi(moduliQ[i].ConvertToInt());
                for (usint j = 0; j < sizeQ - l; j++) {
                    BigInteger qj(moduliQ[l + j].ConvertToInt());
                    BigInteger QlQHatInvModq             = Ql[l] * ((modulusQ.DividedBy(qj)).ModInverse(qj));
                    BigInteger QlQHatInvModqDivq         = QlQHatInvModq / qj;
                    m_QlQHatInvModqDivqModq[l - 1][i][j] = QlQHatInvModqDivq.Mod(qi).ConvertToInt();
                }
                BigInteger QlQHatInvModq                     = Ql[l] * ((modulusQ.DividedBy(qi)).ModInverse(qi));
                BigInteger QlQHatInvModqDivq                 = QlQHatInvModq / qi;
                m_QlQHatInvModqDivqModq[l - 1][i][sizeQ - l] = QlQHatInvModqDivq.Mod(qi).ConvertToInt();
            }
        }

        /////////////////////////////////////
        // BFVrns : Mult : ExpandCRTBasisQlHat
        /////////////////////////////////////

        m_QlHatModq.resize(sizeQ);
        m_QlHatModqPrecon.resize(sizeQ);
        for (usint l = sizeQ; l > 0; l--) {
            m_QlHatModq[l - 1].resize(l);
            m_QlHatModqPrecon[l - 1].resize(l);
            for (usint i = 0; i < l; i++) {
                BigInteger qi(moduliQ[i].ConvertToInt());
                m_QlHatModq[l - 1][i]       = QlHat[l].Mod(qi).ConvertToInt();
                m_QlHatModqPrecon[l - 1][i] = m_QlHatModq[l - 1][i].PrepModMulConst(qi);
            }
        }

        /////////////////////////////////////
        // DropLastElementAndScale
        /////////////////////////////////////

        // Pre-compute omega values for rescaling in RNS
        // modulusQ holds Q^(l) = \prod_{i=0}^{i=l}(q_i).
        m_QlQlInvModqlDivqlModq.resize(sizeQ - 1);
        m_QlQlInvModqlDivqlModqPrecon.resize(sizeQ - 1);
        m_qlInvModq.resize(sizeQ - 1);
        m_qlInvModqPrecon.resize(sizeQ - 1);
        for (size_t k = 0; k < sizeQ - 1; k++) {
            size_t l = sizeQ - (k + 1);
            modulusQ = modulusQ / BigInteger(moduliQ[l]);
            m_QlQlInvModqlDivqlModq[k].resize(l);
            m_QlQlInvModqlDivqlModqPrecon[k].resize(l);
            m_qlInvModq[k].resize(l);
            m_qlInvModqPrecon[k].resize(l);
            BigInteger QlInvModql = modulusQ.ModInverse(moduliQ[l]);
            BigInteger result     = (QlInvModql * modulusQ) / BigInteger(moduliQ[l]);
            for (usint i = 0; i < l; i++) {
                m_QlQlInvModqlDivqlModq[k][i]       = result.Mod(moduliQ[i]).ConvertToInt();
                m_QlQlInvModqlDivqlModqPrecon[k][i] = m_QlQlInvModqlDivqlModq[k][i].PrepModMulConst(moduliQ[i]);
                m_qlInvModq[k][i]                   = moduliQ[l].ModInverse(moduliQ[i]);
                m_qlInvModqPrecon[k][i]             = m_qlInvModq[k][i].PrepModMulConst(moduliQ[i]);
            }
        }
    }

    /////////////////////////////////////
    // BEHZ Precomputation
    /////////////////////////////////////

    if (multTech == BEHZ) {
        m_moduliQ = moduliQ;
        m_numq    = sizeQ;

        std::vector<std::shared_ptr<ILNativeParams>> params;
        params.reserve(2 * sizeQ + 1);
        for (usint i = 0; i < m_numq; ++i)
            params.emplace_back(std::make_shared<ILNativeParams>(2 * n, moduliQ[i]));

        m_moduliB.push_back(PreviousPrime<NativeInteger>(moduliQ.back(), 2 * n));
        m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * n, m_moduliB.back()));
        params.emplace_back(std::make_shared<ILNativeParams>(2 * n, m_moduliB.back(), m_rootsBsk.back()));
        BigInteger B(m_moduliB.back());

        for (usint i = 1; i < m_numq; ++i) {  // we already added one prime
            m_moduliB.push_back(PreviousPrime<NativeInteger>(m_moduliB.back(), 2 * n));
            m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * n, m_moduliB.back()));
            params.emplace_back(std::make_shared<ILNativeParams>(2 * n, m_moduliB.back(), m_rootsBsk.back()));
            B = B * BigInteger(m_moduliB.back());
        }

        m_numb  = m_numq;
        m_msk   = PreviousPrime<NativeInteger>(m_moduliB[m_numq - 1], 2 * n);
        usint s = m_msk.GetMSB();

        BigInteger Q(GetElementParams()->GetModulus());
        BigInteger maxConvolutionValue(BigInteger(2 * n) * BigInteger(GetPlaintextModulus()) * Q);
        // check msk is large enough
        while (B * BigInteger(m_msk) < maxConvolutionValue) {
            // TODO: revisit this logic. Maybe change to m_msk = LastPrime<NativeInteger>(++s, 2 * n);
            auto firstInteger{FirstPrime<NativeInteger>(++s, 2 * n)};
            m_msk = NextPrime<NativeInteger>(firstInteger, 2 * n);
        }
        m_rootsBsk.push_back(RootOfUnity<NativeInteger>(2 * n, m_msk));

        m_moduliBsk = m_moduliB;
        m_moduliBsk.push_back(m_msk);

        params.emplace_back(std::make_shared<ILNativeParams>(2 * n, m_moduliBsk.back(), m_rootsBsk.back()));
        m_paramsQBsk = std::make_shared<ILDCRTParams<BigInteger>>(2 * n, params);

        ChineseRemainderTransformFTT<NativeVector>().PreCompute(m_rootsBsk, 2 * n, m_moduliBsk);

        // populate Barrett constant for m_BskModuli
        m_modbskBarrettMu.resize(m_moduliBsk.size());
        for (uint32_t i = 0; i < m_modbskBarrettMu.size(); i++) {
            m_modbskBarrettMu[i] = (BarrettBase128Bit / BigInteger(m_moduliBsk[i])).ConvertToInt<DoubleNativeInt>();
        }

        // Populate [t*(Q/q_i)^-1]_{q_i}
        m_tQHatInvModq.resize(m_numq);
        m_tQHatInvModqPrecon.resize(m_numq);
        for (uint32_t i = 0; i < m_tQHatInvModq.size(); i++) {
            BigInteger tQHatInvModqi;
            tQHatInvModqi           = Q.DividedBy(moduliQ[i]);
            tQHatInvModqi           = tQHatInvModqi.Mod(moduliQ[i]);
            tQHatInvModqi           = tQHatInvModqi.ModInverse(moduliQ[i]);
            tQHatInvModqi           = tQHatInvModqi.ModMul(t.ConvertToInt(), moduliQ[i]);
            m_tQHatInvModq[i]       = tQHatInvModqi.ConvertToInt();
            m_tQHatInvModqPrecon[i] = m_tQHatInvModq[i].PrepModMulConst(moduliQ[i]);
        }

        // Populate [Q/q_i]_{bsk_j, mtilde}
        m_QHatModbsk.resize(m_numq);
        m_QHatModmtilde.resize(m_numq);
        for (uint32_t i = 0; i < m_QHatModbsk.size(); i++) {
            m_QHatModbsk[i].resize(m_numb + 1);

            BigInteger QHati = Q.DividedBy(moduliQ[i]);
            for (uint32_t j = 0; j < m_QHatModbsk[i].size(); j++) {
                BigInteger QHatiModbskj = QHati.Mod(m_moduliBsk[j]);
                m_QHatModbsk[i][j]      = QHatiModbskj.ConvertToInt();
            }
            m_QHatModmtilde[i] = QHati.Mod(m_mtilde).ConvertToInt();
        }

        // Populate [1/q_i]_{bsk_j}
        m_qInvModbsk.resize(m_numq);
        for (uint32_t i = 0; i < m_qInvModbsk.size(); i++) {
            m_qInvModbsk[i].resize(m_numb + 1);
            for (uint32_t j = 0; j < m_qInvModbsk[i].size(); j++)
                m_qInvModbsk[i][j] = moduliQ[i].ModInverse(m_moduliBsk[j]);
        }

        // Populate [mtilde*(Q/q_i)^{-1}]_{q_i}
        m_mtildeQHatInvModq.resize(m_numq);
        m_mtildeQHatInvModqPrecon.resize(m_numq);

        BigInteger bmtilde(m_mtilde);
        for (uint32_t i = 0; i < m_mtildeQHatInvModq.size(); i++) {
            BigInteger mtildeQHatInvModqi = Q.DividedBy(moduliQ[i]);
            mtildeQHatInvModqi            = mtildeQHatInvModqi.Mod(moduliQ[i]);
            mtildeQHatInvModqi            = mtildeQHatInvModqi.ModInverse(moduliQ[i]);
            mtildeQHatInvModqi            = mtildeQHatInvModqi * bmtilde;
            mtildeQHatInvModqi            = mtildeQHatInvModqi.Mod(moduliQ[i]);
            m_mtildeQHatInvModq[i]        = mtildeQHatInvModqi.ConvertToInt();
            m_mtildeQHatInvModqPrecon[i]  = m_mtildeQHatInvModq[i].PrepModMulConst(moduliQ[i]);
        }

        // Populate [-Q^{-1}]_{mtilde}
        BigInteger negQInvModmtilde = (BigInteger(m_mtilde - 1) * Q.ModInverse(m_mtilde));
        negQInvModmtilde            = negQInvModmtilde.Mod(m_mtilde);
        m_negQInvModmtilde          = negQInvModmtilde.ConvertToInt();

        // Populate [Q]_{bski_j}
        m_QModbsk.resize(m_numq + 1);
        m_QModbskPrecon.resize(m_numq + 1);

        for (uint32_t j = 0; j < m_QModbsk.size(); j++) {
            BigInteger QModbskij = Q.Mod(m_moduliBsk[j]);
            m_QModbsk[j]         = QModbskij.ConvertToInt();
            m_QModbskPrecon[j]   = m_QModbsk[j].PrepModMulConst(m_moduliBsk[j]);
        }

        // Populate [mtilde^{-1}]_{bsk_j}
        m_mtildeInvModbsk.resize(m_numb + 1);
        m_mtildeInvModbskPrecon.resize(m_numb + 1);
        for (uint32_t j = 0; j < m_mtildeInvModbsk.size(); j++) {
            BigInteger mtildeInvModbskij = m_mtilde % m_moduliBsk[j];
            mtildeInvModbskij            = mtildeInvModbskij.ModInverse(m_moduliBsk[j]);
            m_mtildeInvModbsk[j]         = mtildeInvModbskij.ConvertToInt();
            m_mtildeInvModbskPrecon[j]   = m_mtildeInvModbsk[j].PrepModMulConst(m_moduliBsk[j]);
        }

        // Populate {t/Q}_{bsk_j}
        m_tQInvModbsk.resize(m_numb + 1);
        m_tQInvModbskPrecon.resize(m_numb + 1);

        for (uint32_t i = 0; i < m_tQInvModbsk.size(); i++) {
            BigInteger tDivqModBski = Q.ModInverse(m_moduliBsk[i]);
            tDivqModBski.ModMulEq(t.ConvertToInt(), m_moduliBsk[i]);
            m_tQInvModbsk[i]       = tDivqModBski.ConvertToInt();
            m_tQInvModbskPrecon[i] = m_tQInvModbsk[i].PrepModMulConst(m_moduliBsk[i]);
        }

        // Populate [(B/b_j)^{-1}]_{b_j}
        m_BHatInvModb.resize(m_numb);
        m_BHatInvModbPrecon.resize(m_numb);

        for (uint32_t i = 0; i < m_BHatInvModb.size(); i++) {
            BigInteger BDivBi;
            BDivBi                 = B.DividedBy(m_moduliB[i]);
            BDivBi                 = BDivBi.Mod(m_moduliB[i]);
            BDivBi                 = BDivBi.ModInverse(m_moduliB[i]);
            m_BHatInvModb[i]       = BDivBi.ConvertToInt();
            m_BHatInvModbPrecon[i] = m_BHatInvModb[i].PrepModMulConst(m_moduliB[i]);
        }

        // Populate [B/b_j]_{q_i}
        m_BHatModq.resize(m_numb);
        for (uint32_t i = 0; i < m_BHatModq.size(); i++) {
            m_BHatModq[i].resize(m_numq);
            BigInteger BDivBi = B.DividedBy(m_moduliB[i]);
            for (uint32_t j = 0; j < m_BHatModq[i].size(); j++) {
                BigInteger BDivBiModqj = BDivBi.Mod(moduliQ[j]);
                m_BHatModq[i][j]       = BDivBiModqj.ConvertToInt();
            }
        }

        // Populate [B/b_j]_{msk}
        m_BHatModmsk.resize(m_numb);
        for (uint32_t i = 0; i < m_BHatModmsk.size(); i++) {
            BigInteger BDivBi = B.DividedBy(m_moduliB[i]);
            m_BHatModmsk[i]   = (BDivBi.Mod(m_msk)).ConvertToInt();
        }

        // Populate [B^{-1}]_{msk}
        m_BInvModmsk       = (B.ModInverse(m_msk)).ConvertToInt();
        m_BInvModmskPrecon = m_BInvModmsk.PrepModMulConst(m_msk);

        // Populate [B]_{q_i}
        m_BModq.resize(m_numq);
        m_BModqPrecon.resize(m_numq);
        for (uint32_t i = 0; i < m_BModq.size(); i++) {
            m_BModq[i]       = (B.Mod(moduliQ[i])).ConvertToInt();
            m_BModqPrecon[i] = m_BModq[i].PrepModMulConst(moduliQ[i]);
        }

        // Populate Decrns lookup tables

        NativeInteger tgamma = NativeInteger(t.ConvertToInt() * m_gamma);  // t*gamma

        m_tgamma = tgamma;

        // Populate [-1/q_i]_{t*gamma} (t*gamma < 2^58)
        m_negInvqModtgamma.resize(m_numq);
        m_negInvqModtgammaPrecon.resize(m_numq);
        for (uint32_t i = 0; i < m_negInvqModtgamma.size(); i++) {
            BigInteger imod(moduliQ[i]);
            BigInteger negInvqi = BigInteger((tgamma - 1)) * imod.ModInverse(tgamma);

            BigInteger negInvqiModtgamma = negInvqi.Mod(tgamma);
            m_negInvqModtgamma[i]        = negInvqiModtgamma.ConvertToInt();
            m_negInvqModtgammaPrecon[i]  = m_negInvqModtgamma[i].PrepModMulConst(tgamma);
        }

        // populate [t*gamma*(Q/q_i)^(-1)]_{q_i}
        m_tgammaQHatInvModq.resize(m_numq);
        m_tgammaQHatInvModqPrecon.resize(m_numq);

        BigInteger bmgamma(m_gamma);
        for (uint32_t i = 0; i < m_tgammaQHatInvModq.size(); i++) {
            BigInteger qDivqi = Q.DividedBy(moduliQ[i]);
            BigInteger imod(moduliQ[i]);
            qDivqi                       = qDivqi.ModInverse(moduliQ[i]);
            BigInteger gammaqDivqi       = (qDivqi * bmgamma) % imod;
            BigInteger tgammaqDivqi      = (gammaqDivqi * BigInteger(t)) % imod;
            m_tgammaQHatInvModq[i]       = tgammaqDivqi.ConvertToInt();
            m_tgammaQHatInvModqPrecon[i] = m_tgammaQHatInvModq[i].PrepModMulConst(moduliQ[i]);
        }
    }
}

uint64_t CryptoParametersBFVRNS::FindAuxPrimeStep() const {
    return 2 * GetElementParams()->GetRingDimension();
}

}  // namespace lbcrypto
