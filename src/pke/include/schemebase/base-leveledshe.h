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

#ifndef LBCRYPTO_CRYPTO_BASE_LEVELEDSHE_H
#define LBCRYPTO_CRYPTO_BASE_LEVELEDSHE_H

#include "lattice/lat-hal.h"
#include "key/publickey-fwd.h"
#include "key/privatekey-fwd.h"
#include "key/evalkey-fwd.h"
#include "encoding/plaintext-fwd.h"
#include "ciphertext-fwd.h"
#include "utils/caller_info.h"
#include "utils/inttypes.h"
#include "utils/exception.h"

#include <memory>
#include <vector>
#include <map>
#include <string>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
/**
 * @brief Abstract interface class for LBC SHE algorithms
 * @tparam Element a ring element.
 */
template <class Element>
class LeveledSHEBase {
    using ParmType = typename Element::Params;
    using IntType  = typename Element::Integer;
    using DugType  = typename Element::DugType;
    using DggType  = typename Element::DggType;
    using TugType  = typename Element::TugType;

public:
    virtual ~LeveledSHEBase() {}

    /////////////////////////////////////////
    // SHE NEGATION
    /////////////////////////////////////////

    /**
   * Virtual function to define the homomorphic negation of
   * ciphertext.
   *
   * @param &ciphertext the input ciphertext.
   * @return new ciphertext.
   */
    virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const;

    /**
   * Virtual function to define the interface for homomorphic negation of
   * ciphertext.
   *
   * @param &ciphertext the input ciphertext.
   * @return new ciphertext.
   */
    virtual void EvalNegateInPlace(Ciphertext<Element>& ciphertext) const;

    /////////////////////////////////////////
    // SHE ADDITION
    /////////////////////////////////////////

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const;

    /**
   * Virtual function to define the interface for in-place homomorphic addition
   * of ciphertexts.
   *
   * @param ciphertext1 the input/output ciphertext.
   * @param ciphertext2 the input ciphertext.
   */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertexts may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext1,
                                               Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("EvalAddMutable is not implemented for this scheme");
    }

    virtual void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("EvalAddMutable is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const;

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalAddMutable is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for homomorphic addition of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalAddMutable is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar addition is not implemented for this scheme");
    }

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar addition is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const {
        OPENFHE_THROW("double scalar addition is not implemented for this scheme");
    }

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        OPENFHE_THROW("double scalar addition is not implemented for this scheme");
    }

    /////////////////////////////////////////
    // SHE SUBTRACTION
    /////////////////////////////////////////

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   */
    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1,
                                               Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("EvalSubMutable is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("EvalSubMutable is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const;

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const;

    /**
   * Virtual function to define the interface for homomorphic subtraction of
   * ciphertexts. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalSubMutable is not implemented for this scheme");
    }

    virtual void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalSubMutable is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar subtraction is not implemented for this scheme");
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar subtraction is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, double constant) const {
        OPENFHE_THROW("double scalar subtraction is not implemented for this scheme");
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        OPENFHE_THROW("double scalar subtraction is not implemented for this scheme");
    }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION
    //------------------------------------------------------------------------------

    /**
   * Virtual function to define the interface for generating a evaluation key
   * which is used after each multiplication.
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @param *newCiphertext the new resulting ciphertext.
   */
    virtual EvalKey<Element> EvalMultKeyGen(const PrivateKey<Element> privateKey) const;

    /**
   * Virtual function to define the interface for generating a evaluation key
   * which is used after each multiplication for depth more than 2.
   *
   * @param &originalPrivateKey Original private key used for encryption.
   * @param *evalMultKeys the resulting evalution key vector list.
   */
    virtual std::vector<EvalKey<Element>> EvalMultKeysGen(const PrivateKey<Element> privateKey) const;

    //------------------------------------------------------------------------------
    // EVAL MULTIPLICATION CIPHERTEXT & CIPHERTEXT
    //------------------------------------------------------------------------------

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                         ConstCiphertext<Element> ciphertext2) const {
        OPENFHE_THROW("EvalMult is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext. This is the mutable version - input ciphertexts
   * may change (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1,
                                                Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("EvalMultMutable is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext.
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext1) const {
        OPENFHE_THROW("EvalSquare is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext. This is the mutable version - input ciphertexts
   * may change (automatically rescaled, or towers dropped).
   *
   * @param ciphertext1 the input ciphertext.
   * @param ciphertext2 the input ciphertext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext1) const {
        OPENFHE_THROW("EvalSquareMutable is not implemented for this scheme");
    }

    //------------------------------------------------------------------------------
    // EVAL MULTIPLICATION CIPHERTEXT & PLAINTEXT
    //------------------------------------------------------------------------------

    /**
   * Virtual function to define the interface for multiplication of ciphertext
   * by plaintext.
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const;

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const;

    /**
   * Virtual function to define the interface for multiplication of ciphertext
   * by plaintext. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalMultMutable C,P is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for multiplication of ciphertext
   * by plaintext. This is the mutable version - input ciphertext may change
   * (automatically rescaled, or towers dropped).
   *
   * @param ciphertext the input ciphertext.
   * @param plaintext the input plaintext.
   * @return the new ciphertext.
   */
    virtual void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        OPENFHE_THROW("EvalMultMutableInPlace C P is not implemented for this scheme");
    }

    virtual Ciphertext<Element> MultByMonomial(ConstCiphertext<Element> ciphertext, usint power) const {
        OPENFHE_THROW("MultByMonomial is not implemented for this scheme");
    }

    virtual void MultByMonomialInPlace(Ciphertext<Element>& ciphertext, usint power) const {
        OPENFHE_THROW("MultByMonomialInPlace is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar multiplication is not implemented for this scheme");
    }

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
        OPENFHE_THROW("integer scalar multiplication is not implemented for this scheme");
    }

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, double constant) const {
        OPENFHE_THROW("double scalar multiplication is not implemented for this scheme");
    }

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        OPENFHE_THROW("double scalar multiplication is not implemented for this scheme");
    }

    virtual Ciphertext<DCRTPoly> MultByInteger(ConstCiphertext<DCRTPoly> ciphertext, uint64_t integer) const {
        OPENFHE_THROW("MultByInteger is not implemented for this scheme");
    }

    virtual void MultByIntegerInPlace(Ciphertext<DCRTPoly>& ciphertext, uint64_t integer) const {
        OPENFHE_THROW("MultByIntegerInPlace is not implemented for this scheme");
    }

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key.
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
                                         const EvalKey<Element> evalKey) const;

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2,
                                 const EvalKey<Element> evalKey) const;

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key. This is the mutable
   * version - input ciphertext may change (automatically rescaled, or towers
   * dropped).
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return the new ciphertext.
   */
    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                const EvalKey<Element> evalKey) const;

    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key. This is the mutable
   * version - input ciphertext may change (automatically rescaled, or towers
   * dropped).
   *
   * @param &ciphertext1 first input ciphertext.
   * @param &ciphertext2 second input ciphertext.
   * @param &ek is the evaluation key to make the newCiphertext decryptable by
   * the same secret key as that of ciphertext1 and ciphertext2.
   * @return the new ciphertext.
   */
    virtual void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                        const EvalKey<Element> evalKey) const;

    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const;

    virtual void EvalSquareInPlace(Ciphertext<Element>& ciphertext1, const EvalKey<Element> evalKey) const;

    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext,
                                                  const EvalKey<Element> evalKey) const;
    /**
   * Virtual function to define the interface for multiplicative homomorphic
   * evaluation of ciphertext using the evaluation key.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   * @param ek is the evaluation key to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @param *newCiphertext the new resulting ciphertext.
   */
    virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ciphertext1,
                                                       ConstCiphertext<Element> ciphertext2,
                                                       const std::vector<EvalKey<Element>>& evalKeyVec) const;

    /**
   * Virtual function to do relinearization
   *
   * @param ciphertext input ciphertext.
   * @param ek are the evaluation keys to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @return the new resulting ciphertext.
   */
    virtual Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext,
                                            const std::vector<EvalKey<Element>>& evalKeyVec) const;

    /**
   * Virtual function to do relinearization
   *
   * @param ciphertext input ciphertext.
   * @param ek are the evaluation keys to make the newCiphertext
   *  decryptable by the same secret key as that of ciphertext1 and
   * ciphertext2.
   * @return the new resulting ciphertext.
   */
    virtual void RelinearizeInPlace(Ciphertext<Element>& ciphertext,
                                    const std::vector<EvalKey<Element>>& evalKeyVec) const;

    //------------------------------------------------------------------------------
    // SHE AUTOMORPHISM
    //------------------------------------------------------------------------------

    /**
   * Virtual function to generate automophism keys for a given private key;
   * Uses the private key for encryption
   *
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::vector<usint>& indexList) const;

    /**
   * Virtual function to generate all isomorphism keys for a given private key
   *
   * @param publicKey encryption key for the new ciphertext.
   * @param origPrivateKey original private key used for decryption.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
        const std::vector<usint>& indexList) const {
        std::string errMsg = "EvalAutomorphismKeyGen is not implemented for this scheme.";
        OPENFHE_THROW(errMsg);
    }

    /**
   * Virtual function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the vector of evaluation keys generated
   * by EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
                                                 const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                                 CALLER_INFO_ARGS_HDR) const;

    /**
   * Virtual function for the automorphism and key switching step of
   * hoisted automorphisms.
   *
   * @param ct the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to
   * left rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param digits the digit decomposition created by
   * EvalFastRotationPrecompute at the precomputation step.
   */
    virtual Ciphertext<Element> EvalFastRotation(ConstCiphertext<Element> ciphertext, const usint index, const usint m,
                                                 const std::shared_ptr<std::vector<Element>> digits) const;

    /**
   * Virtual function for the precomputation step of hoisted
   * automorphisms.
   *
   * @param ct the input ciphertext on which to do the precomputation (digit
   * decomposition)
   */
    virtual std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(ConstCiphertext<Element> ciphertext) const;

    virtual Ciphertext<Element> EvalFastRotationExt(ConstCiphertext<Element> ciphertext, usint index,
                                                    const std::shared_ptr<std::vector<Element>> expandedCiphertext,
                                                    bool addFirst,
                                                    const std::map<usint, EvalKey<Element>>& evalKeys) const {
        std::string errMsg = "EvalFastRotationExt is not implemented for this scheme.";
        OPENFHE_THROW(errMsg);
    }

    /**
   * Generates evaluation keys for a list of indices
   * Currently works only for power-of-two and cyclic-group cyclotomics
   *
   * @param publicKey encryption key for the new ciphertext.
   * @param origPrivateKey original private key used for decryption.
   * @param indexList list of indices to be computed
   * @return returns the evaluation keys
   */
    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAtIndexKeyGen(
        const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
        const std::vector<int32_t>& indexList) const;

    /**
   * Moves i-th slot to slot 0
   *
   * @param ciphertext.
   * @param i the index.
   * @param &evalAtIndexKeys - reference to the map of evaluation keys
   * generated by EvalAtIndexKeyGen.
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index,
                                            const std::map<usint, EvalKey<Element>>& evalKeyMap) const;

    virtual usint FindAutomorphismIndex(usint index, usint m) const {
        OPENFHE_THROW("FindAutomorphismIndex is not supported for this scheme");
    }

    /////////////////////////////////////////
    // SHE LEVELED Mod Reduce
    /////////////////////////////////////////

    /**
   * Method for Modulus Reduction.
   *
   * @param &cipherText Ciphertext to perform mod reduce on.
   * @param levels the number of towers to drop.
   */
    virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext, size_t levels) const {
        OPENFHE_THROW("ModReduce is not supported for this scheme");
    }

    /**
   * Method for In-place Modulus Reduction.
   *
   * @param &cipherText Ciphertext to perform mod reduce on.
   * @param levels the number of towers to drop.
   */
    virtual void ModReduceInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW("ModReduce is not supported for this scheme");
    }

    /**
   * Method for Composed EvalMult
   *
   * @param &cipherText1 ciphertext1, first input ciphertext to perform
   * multiplication on.
   * @param &cipherText2 cipherText2, second input ciphertext to perform
   * multiplication on.
   * @param &quadKeySwitchHint is for resultant quadratic secret key after
   * multiplication to the secret key of the particular level.
   * @param &cipherTextResult is the resulting ciphertext that can be
   * decrypted with the secret key of the particular level.
   */
    virtual Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2,
                                                 const EvalKey<Element> evalKey) const;

    /**
   * Method for Level Reduction from sk -> sk1. This method peforms a
   * keyswitch on the ciphertext and then performs a modulus reduction.
   *
   * @param &cipherText1 is the original ciphertext to be key switched and mod
   * reduced.
   * @param &linearKeySwitchHint is the linear key switch hint to perform the
   * key switch operation.
   * @param &cipherTextResult is the resulting ciphertext.
   */
    virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext1, const EvalKey<Element> evalKey,
                                            size_t levels) const;

    /**
   * Method for Level Reduction from sk -> sk1. This method peforms a
   * keyswitch on the ciphertext and then performs a modulus reduction.
   *
   * @param &cipherText1 is the original ciphertext to be key switched and mod
   * reduced.
   * @param &linearKeySwitchHint is the linear key switch hint to perform the
   * key switch operation.
   * @param &cipherTextResult is the resulting ciphertext.
   */
    virtual void LevelReduceInPlace(Ciphertext<Element>& ciphertext1, const EvalKey<Element> evalKey,
                                    size_t levels) const {
        OPENFHE_THROW("LevelReduceInPlace is not supported for this scheme");
    }

    virtual Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext, size_t towersLeft) const {
        OPENFHE_THROW("Compress is not supported for this scheme");
    }

    /**
   * Method for rescaling.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @return ciphertext after the modulus reduction performed.
   */
    virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
        OPENFHE_THROW("ModReduce is not supported for this scheme");
    }

    /**
   * Method for rescaling in-place.
   *
   * @param cipherText is the ciphertext to perform modreduce on.
   * @param levels the number of towers to drop.
   * @details \p cipherText will have modulus reduction performed in-place.
   */
    virtual void ModReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW("ModReduce is not supported for this scheme");
    }

    /**
   * Method for Level Reduction in the CKKS scheme. It just drops "levels"
   * number of the towers of the ciphertext without changing the underlying
   * plaintext.
   *
   * @param cipherText1 is the original ciphertext to be level reduced.
   * @param levels the number of towers to drop.
   * @return resulting ciphertext.
   */
    virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
        OPENFHE_THROW("LevelReduce is not supported for this scheme");
    }

    /**
   * Method for in-place Level Reduction in the CKKS scheme. It just drops
   * "levels" number of the towers of the ciphertext without changing the
   * underlying plaintext.
   *
   * @param cipherText1 is the ciphertext to be level reduced in-place
   * @param levels the number of towers to drop.
   */
    virtual void LevelReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW("LevelReduce is not supported for this scheme");
    }

    virtual void AdjustLevelsInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("Leveled Operations are not supported for this scheme");
    }

    virtual void AdjustLevelsAndDepthInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("Mutable Operations are not supported for this scheme");
    }

    virtual void AdjustLevelsAndDepthToOneInPlace(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("Mutable Operations are not supported for this scheme");
    }

    // TODO (Andrey) : Move these functions to protected or to rns?
    virtual void AdjustForAddOrSubInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("Mutable Operations are not supported for this scheme");
    }

    virtual void AdjustForMultInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW("Mutable Operations are not supported for this scheme");
    }

    virtual Ciphertext<Element> MorphPlaintext(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const;

protected:
    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////

    /**
   * Internal function for in-place homomorphic addition of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return \p ciphertext1 contains the result of the homomorphic addition of
   * input ciphertexts.
   */
    virtual Ciphertext<Element> EvalAddCore(ConstCiphertext<Element> ciphertext1,
                                            ConstCiphertext<Element> ciphertext2) const;

    /**
   * Internal function for in-place homomorphic addition of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return \p ciphertext1 contains the result of the homomorphic addition of
   * input ciphertexts.
   */
    void EvalAddCoreInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const;

    virtual Ciphertext<Element> EvalSubCore(ConstCiphertext<Element> ciphertext1,
                                            ConstCiphertext<Element> ciphertext2) const;

    /**
   * Internal function for in-place homomorphic addition of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input/output ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return \p ciphertext1 contains the result of the homomorphic addition of
   * input ciphertexts.
   */
    void EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const;

    /**
   * Internal function for homomorphic multiplication of ciphertexts.
   * This method does not check whether input ciphertexts are
   * at the same level.
   *
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return result of homomorphic multiplication of input ciphertexts.
   */
    Ciphertext<Element> EvalMultCore(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const;

    Ciphertext<Element> EvalSquareCore(ConstCiphertext<Element> ciphertext) const;

    virtual Ciphertext<Element> EvalAddCore(ConstCiphertext<Element> ciphertext, const Element plaintext) const;

    void EvalAddCoreInPlace(Ciphertext<Element>& ciphertext, const Element plaintext) const;

    virtual Ciphertext<Element> EvalSubCore(ConstCiphertext<Element> ciphertext1, const Element plaintext) const;

    void EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1, const Element plaintext) const;

    Ciphertext<Element> EvalMultCore(ConstCiphertext<Element> ciphertext, const Element plaintext) const;

    void EvalMultCoreInPlace(Ciphertext<Element>& ciphertext, const Element plaintext) const;
};

}  // namespace lbcrypto

#endif
