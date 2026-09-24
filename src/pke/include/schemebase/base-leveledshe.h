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

#ifndef SRC_PKE_INCLUDE_SCHEMEBASE_BASE_LEVELEDSHE_H_
#define SRC_PKE_INCLUDE_SCHEMEBASE_BASE_LEVELEDSHE_H_

#include <complex>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "ciphertext-fwd.h"
#include "encoding/plaintext-fwd.h"
#include "key/evalkey-fwd.h"
#include "key/privatekey-fwd.h"
#include "key/publickey-fwd.h"
#include "lattice/lat-hal.h"
#include "utils/caller_info.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

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
    using IntType = typename Element::Integer;
    using DugType = typename Element::DugType;
    using DggType = typename Element::DggType;
    using TugType = typename Element::TugType;

    // TODO: should we use just one error message instead of two (see below)
    constexpr static std::string_view NOT_IMPLEMENTED_ERROR = "Not implemented for this scheme";
    constexpr static std::string_view NOT_SUPPORTED_ERROR = "Not supported for this scheme";

  public:
    virtual ~LeveledSHEBase() = default;

    /////////////////////////////////////////
    // SHE NEGATION
    /////////////////////////////////////////

    /**
     * Virtual function to define the homomorphic negation of
     * ciphertext.
     *
     * @param ciphertext the input ciphertext.
     * @return new ciphertext.
     */
    virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element>& ciphertext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic negation of
     * ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
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
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext1,
                                        ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for in-place homomorphic addition
     * of ciphertexts.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

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
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for homomorphic addition of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of
     * a ciphertext and a plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic addition of an integer scalar to a ciphertext.
     * Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic addition of an integer scalar
     * to a ciphertext. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar to add.
     */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Adds a real constant to every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place addition of a real constant to every slot of a ciphertext (CKKS): the constant is scaled
     * by the scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant to add.
     */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Adds a complex constant to every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the complex constant to add.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place addition of a complex constant to every slot of a ciphertext (CKKS): the constant is scaled
     * by the scaling factor of the ciphertext and added to its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the complex constant to add.
     */
    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
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
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext1,
                                        ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext1 the input ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

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
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertexts may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param ciphertext2 the input ciphertext.
     */
    virtual void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for homomorphic subtraction of
     * ciphertexts. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of
     * a plaintext from a ciphertext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic subtraction of an integer scalar from
     * a ciphertext. Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar to subtract.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place homomorphic subtraction of an integer scalar
     * from a ciphertext. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar to subtract.
     */
    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Subtracts a real constant from every slot of a ciphertext (CKKS): the constant is scaled by the
     * scaling factor of the ciphertext and subtracted from its first element.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant to subtract.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place subtraction of a real constant from every slot of a ciphertext (CKKS): the constant is
     * scaled by the scaling factor of the ciphertext and subtracted from its first element.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant to subtract.
     */
    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION
    //------------------------------------------------------------------------------

    /**
     * Virtual function to define the interface for generating an evaluation key
     * which is used after each multiplication.
     *
     * @param privateKey the private key the relinearization key is generated for.
     * @return the relinearization (evaluation) key for s^2.
     */
    virtual EvalKey<Element> EvalMultKeyGen(const PrivateKey<Element> privateKey) const;

    /**
     * Virtual function to define the interface for generating a evaluation key
     * which is used after each multiplication for depth more than 2.
     *
     * @param privateKey the private key the relinearization keys are generated for.
     * @return the vector of relinearization (evaluation) keys for s^2, s^3, ...
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
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
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
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic squaring
     * of ciphertext.
     *
     * @param ciphertext1 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element>& ciphertext1) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for homomorphic squaring
     * of ciphertext. This is the mutable version - input ciphertext
     * may change (automatically rescaled, or towers dropped).
     *
     * @param ciphertext1 the input ciphertext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext1) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
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
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for in-place multiplication of a ciphertext
     * by a plaintext: every ciphertext element is multiplied by the plaintext polynomial
     * (in EVALUATION format).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext& plaintext) const;

    /**
     * Virtual function to define the interface for multiplication of ciphertext
     * by plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the input plaintext.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place multiplication of ciphertext
     * by plaintext. This is the mutable version - input ciphertext may change
     * (automatically rescaled, or towers dropped).
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the input plaintext.
     */
    virtual void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext, Plaintext& plaintext) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies the ciphertext by the monomial x^power of the cyclotomic ring, i.e., performs a
     * negacyclic shift of the encrypted coefficients (power is reduced modulo 2N; powers in [N, 2N)
     * flip the sign). The scaling factor and noise are not changed.
     *
     * @param ciphertext the input ciphertext.
     * @param power the exponent of the monomial.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> MultByMonomial(ConstCiphertext<Element>& ciphertext, uint32_t power) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of the ciphertext by the monomial x^power of the cyclotomic ring
     * (negacyclic shift of the encrypted coefficients); see MultByMonomial.
     *
     * @param ciphertext the input/output ciphertext.
     * @param power the exponent of the monomial.
     */
    virtual void MultByMonomialInPlace(Ciphertext<Element>& ciphertext, uint32_t power) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for multiplication of a ciphertext by an integer scalar.
     * Not implemented by any of the current schemes; the base implementation throws NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the integer scalar.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for in-place multiplication of a ciphertext by an integer
     * scalar. Not implemented by any of the current schemes; the base implementation throws
     * NOT_IMPLEMENTED_ERROR.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the integer scalar.
     */
    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, NativeInteger scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies a ciphertext by a real constant (CKKS): the constant is encoded at the scaling factor
     * of the current level, so the noise scale degree of the result is one higher than that of the input
     * (the automatic scaling techniques first rescale an input of noise scale degree 2).
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the real constant.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of a ciphertext by a real constant (CKKS); see EvalMult.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the real constant.
     */
    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies a ciphertext by a complex constant (CKKS): the constant is encoded at the scaling factor
     * of the current level, so the noise scale degree of the result is one higher than that of the input
     * (the automatic scaling techniques first rescale an input of noise scale degree 2).
     *
     * @param ciphertext the input ciphertext.
     * @param scalar the complex constant.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of a ciphertext by a complex constant (CKKS); see EvalMult.
     *
     * @param ciphertext the input/output ciphertext.
     * @param scalar the complex constant.
     */
    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Multiplies every element of the ciphertext by a positive integer without encoding it at the
     * scaling factor: the encrypted values are scaled by the integer exactly and the scaling factor and
     * noise scale degree of the ciphertext are left unchanged (CKKS).
     *
     * @param ciphertext the input ciphertext.
     * @param integer the positive integer to multiply by.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> MultByInteger(ConstCiphertext<Element>& ciphertext, uint64_t integer) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * In-place multiplication of every element of the ciphertext by a positive integer without changing
     * the scaling factor or the noise scale degree (CKKS); see MultByInteger.
     *
     * @param ciphertext the input/output ciphertext.
     * @param integer the positive integer to multiply by.
     */
    virtual void MultByIntegerInPlace(Ciphertext<Element>& ciphertext, uint64_t integer) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext using the evaluation key.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey is the evaluation key to make the new ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     * @return the new ciphertext.
     */
    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                         const EvalKey<Element> evalKey) const;

    /**
     * Virtual function to define the interface for in-place multiplicative homomorphic
     * evaluation of ciphertexts followed by relinearization with the evaluation key
     * (the third element of the product is key switched back to two elements).
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey is the evaluation key to make the resulting ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     */
    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2,
                                 const EvalKey<Element> evalKey) const;

    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext using the evaluation key. This is the mutable
     * version - input ciphertext may change (automatically rescaled, or towers
     * dropped).
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey is the evaluation key to make the new ciphertext decryptable by
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
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKey is the evaluation key to make the resulting ciphertext decryptable by
     * the same secret key as that of ciphertext1 and ciphertext2.
     */
    virtual void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                        const EvalKey<Element> evalKey) const;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     *
     * @param ciphertext the input ciphertext.
     * @param evalKey the relinearization key for s^2.
     * @return the new ciphertext with two elements.
     */
    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const;

    /**
     * In-place homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param evalKey the relinearization key for s^2.
     */
    virtual void EvalSquareInPlace(Ciphertext<Element>& ciphertext1, const EvalKey<Element> evalKey) const;

    /**
     * Homomorphic squaring of a ciphertext followed by relinearization with the evaluation key.
     * This is the mutable version - the input ciphertext may change (automatically rescaled,
     * or towers dropped).
     *
     * @param ciphertext the input ciphertext.
     * @param evalKey the relinearization key for s^2.
     * @return the new ciphertext with two elements.
     */
    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext,
                                                  const EvalKey<Element> evalKey) const;
    /**
     * Virtual function to define the interface for multiplicative homomorphic
     * evaluation of ciphertext followed by relinearization using the evaluation keys.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @param evalKeyVec are the evaluation keys to make the new ciphertext
     *  decryptable by the same secret key as that of ciphertext1 and
     * ciphertext2.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element>& ciphertext1,
                                                       ConstCiphertext<Element>& ciphertext2,
                                                       const std::vector<EvalKey<Element>>& evalKeyVec) const;

    /**
     * Virtual function to do relinearization
     *
     * @param ciphertext input ciphertext.
     * @param evalKeyVec are the evaluation keys to make the new ciphertext
     *  decryptable by the same secret key as that of the input ciphertext.
     * @return the new resulting ciphertext.
     */
    virtual Ciphertext<Element> Relinearize(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<EvalKey<Element>>& evalKeyVec) const;

    /**
     * Virtual function to do relinearization in-place
     *
     * @param ciphertext input/output ciphertext.
     * @param evalKeyVec are the evaluation keys to make the resulting ciphertext
     *  decryptable by the same secret key as that of the input ciphertext.
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
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalAutomorphismKeyGen(
            const PrivateKey<Element> privateKey, const std::vector<uint32_t>& indexList) const;

    /**
     * Virtual function for evaluating automorphism of ciphertext at index i
     *
     * @param ciphertext the input ciphertext.
     * @param i automorphism index
     * @param evalKeyMap - reference to the map of evaluation keys generated by EvalAutomorphismKeyGen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                                 const std::map<uint32_t, EvalKey<Element>>& evalKeyMap,
                                                 CALLER_INFO_ARGS_HDR) const;

    /**
     * Shared core for evaluating an automorphism from precomputed key-switch digits.
     * Both EvalAutomorphism and EvalFastRotation delegate here, so every rotation
     * entry point (EvalRotate/EvalAtIndex, hoisted fast rotations, conjugation)
     * applies the same operation sequence and produces bit-identical ciphertexts.
     *
     * @param ciphertext the input ciphertext.
     * @param autoIndex automorphism index.
     * @param digits the digit decomposition of the second ciphertext element,
     * as produced by EvalFastRotationPrecompute.
     * @param evalKey the automorphism key for autoIndex.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> EvalAutomorphismCore(ConstCiphertext<Element>& ciphertext, uint32_t autoIndex,
                                                     const std::shared_ptr<std::vector<Element>>& digits,
                                                     const EvalKey<Element>& evalKey) const;

    /**
     * Virtual function for the automorphism and key switching step of
     * hoisted automorphisms.
     *
     * @param ciphertext the input ciphertext to perform the automorphism on
     * @param index the index of the rotation. Positive indices correspond to
     * left rotations and negative indices correspond to right rotations.
     * @param m is the cyclotomic order
     * @param digits the digit decomposition created by
     * EvalFastRotationPrecompute at the precomputation step.
     * @return the rotated ciphertext
     */
    virtual Ciphertext<Element> EvalFastRotation(ConstCiphertext<Element>& ciphertext, const uint32_t index,
                                                 const uint32_t m,
                                                 const std::shared_ptr<std::vector<Element>> digits) const;

    /**
     * Virtual function for the precomputation step of hoisted
     * automorphisms.
     *
     * @param ciphertext the input ciphertext on which to do the precomputation (digit
     * decomposition)
     * @return the digit decomposition of the ciphertext
     */
    virtual std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(
            ConstCiphertext<Element>& ciphertext) const;

    /**
     * Hoisted (fast) rotation in the extended CRT basis Q*P, supported only with HYBRID key switching:
     * applies the key switching for the automorphism of rotation index \p index to the precomputed
     * digit decomposition and then the automorphism itself. The result stays in the extended basis
     * (see KeySwitchDown), which lets several rotations be accumulated with a single modulus reduction.
     *
     * @param ciphertext the input ciphertext.
     * @param index the rotation index (positive for left, negative for right).
     * @param expandedCiphertext the digit decomposition of the second ciphertext element in the extended
     * basis, as produced by EvalFastRotationPrecompute.
     * @param addFirst if true, the first ciphertext element (scaled up by P) is added to the result so
     * that it is a complete ciphertext; if false, only the key-switched part is returned.
     * @param evalKeys the map of automorphism keys generated by EvalAutomorphismKeyGen.
     * @return the rotated ciphertext in the extended basis Q*P.
     */
    virtual Ciphertext<Element> EvalFastRotationExt(ConstCiphertext<Element>& ciphertext, uint32_t index,
                                                    const std::shared_ptr<std::vector<Element>> expandedCiphertext,
                                                    bool addFirst,
                                                    const std::map<uint32_t, EvalKey<Element>>& evalKeys) const {
        OPENFHE_THROW(NOT_IMPLEMENTED_ERROR);
    }

    /**
     * Generates evaluation keys for a list of indices
     * Currently works only for power-of-two and cyclic-group cyclotomics
     *
     * @param privateKey private key the rotation keys are generated for.
     * @param indexList list of indices to be computed
     * @return returns the evaluation keys
     */
    virtual std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalAtIndexKeyGen(
            const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList) const;

    /**
     * Rotates the slots of the ciphertext by index
     *
     * @param ciphertext the input ciphertext.
     * @param index the rotation index (positive for left, negative for right).
     * @param evalKeyMap - reference to the map of evaluation keys
     * generated by EvalAtIndexKeyGen.
     * @return resulting ciphertext
     */
    virtual Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element>& ciphertext, int32_t index,
                                            const std::map<uint32_t, EvalKey<Element>>& evalKeyMap) const;

    /**
     * Maps a rotation index to the automorphism index (Galois element) that realizes it for the
     * cyclotomic order m; the mapping depends on the packing of the scheme (real packing for BGV/BFV,
     * complex packing for CKKS).
     *
     * @param index the rotation index (positive for left, negative for right).
     * @param m the cyclotomic order.
     * @return the automorphism index.
     */
    virtual uint32_t FindAutomorphismIndex(uint32_t index, uint32_t m) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /////////////////////////////////////////
    // SHE LEVELED Mod Reduce
    /////////////////////////////////////////

    /**
     * Method for Modulus Reduction.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction.
     */
    virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for In-place Modulus Reduction.
     *
     * @param ciphertext Ciphertext to perform mod reduce on.
     * @param levels the number of towers to drop.
     */
    virtual void ModReduceInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for Composed EvalMult (multiplication, relinearization and modulus reduction)
     *
     * @param ciphertext1 first input ciphertext to perform
     * multiplication on.
     * @param ciphertext2 second input ciphertext to perform
     * multiplication on.
     * @param evalKey is the relinearization key for the quadratic secret key after
     * multiplication.
     * @return the resulting ciphertext that can be
     * decrypted with the secret key of the particular level.
     */
    virtual Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element>& ciphertext1,
                                                 ConstCiphertext<Element>& ciphertext2,
                                                 const EvalKey<Element> evalKey) const;

    /**
     * Method for Level Reduction. Drops the given number of towers of the ciphertext
     * without changing the underlying plaintext.
     *
     * @param ciphertext1 is the original ciphertext to be level reduced.
     * @param evalKey evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     * @return the resulting ciphertext.
     */
    virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element>& ciphertext1, const EvalKey<Element> evalKey,
                                            size_t levels) const;

    /**
     * Method for in-place Level Reduction. Drops the given number of towers of the
     * ciphertext without changing the underlying plaintext.
     *
     * @param ciphertext1 is the ciphertext to be level reduced in-place.
     * @param evalKey evaluation key (currently unused; kept for API compatibility).
     * @param levels the number of towers to drop.
     */
    virtual void LevelReduceInPlace(Ciphertext<Element>& ciphertext1, const EvalKey<Element> evalKey,
                                    size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Compresses a ciphertext to reduce its size for communication: rescales it until its noise scale
     * degree is at most \p noiseScaleDeg and then drops towers until \p towersLeft towers remain.
     * For the composite scaling techniques, \p towersLeft must be a multiple of the composite degree.
     *
     * @param ciphertext the input ciphertext.
     * @param towersLeft the number of RNS towers to keep.
     * @param noiseScaleDeg the noise scale degree the ciphertext is rescaled to before towers are dropped.
     * @return the compressed ciphertext.
     */
    virtual Ciphertext<Element> Compress(ConstCiphertext<Element>& ciphertext, size_t towersLeft,
                                         size_t noiseScaleDeg) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for rescaling.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @return ciphertext after the modulus reduction performed.
     */
    virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for rescaling in-place.
     *
     * @param ciphertext is the ciphertext to perform modreduce on.
     * @param levels the number of towers to drop.
     * @details \p ciphertext will have modulus reduction performed in-place.
     */
    virtual void ModReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for Level Reduction in the CKKS scheme. It just drops "levels"
     * number of the towers of the ciphertext without changing the underlying
     * plaintext.
     *
     * @param ciphertext is the original ciphertext to be level reduced.
     * @param levels the number of towers to drop.
     * @return resulting ciphertext.
     */
    virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Method for in-place Level Reduction in the CKKS scheme. It just drops
     * "levels" number of the towers of the ciphertext without changing the
     * underlying plaintext.
     *
     * @param ciphertext is the ciphertext to be level reduced in-place
     * @param levels the number of towers to drop.
     */
    virtual void LevelReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same number of RNS towers by dropping towers from the one with
     * more towers (LevelReduceInternalInPlace); noise scale degrees are not changed.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void AdjustLevelsInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same level and noise scale degree so that they can be added or
     * subtracted (used by the automatic scaling techniques): the ciphertext at the lower level or
     * degree is rescaled, or multiplied by the appropriate scaling factor, and level reduced as needed.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void AdjustLevelsAndDepthInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Brings two ciphertexts to the same level and noise scale degree as AdjustLevelsAndDepthInPlace and
     * then rescales both to noise scale degree 1 if they are at degree 2; used before a multiplication.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void AdjustLevelsAndDepthToOneInPlace(Ciphertext<Element>& ciphertext1,
                                                  Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    // TODO (Andrey) : Move these functions to protected or to rns?
    /**
     * Prepares two operands for addition or subtraction according to the scaling technique: FIXEDMANUAL
     * only matches the number of towers (and scales a single-element operand obtained from a plaintext up
     * to the noise scale degree of the other operand); the automatic techniques call
     * AdjustLevelsAndDepthInPlace; NORESCALE does nothing.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void AdjustForAddOrSubInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Prepares two operands for multiplication according to the scaling technique: FIXEDMANUAL only
     * matches the number of towers; the automatic techniques call AdjustLevelsAndDepthToOneInPlace;
     * NORESCALE does nothing.
     *
     * @param ciphertext1 first input/output ciphertext.
     * @param ciphertext2 second input/output ciphertext.
     */
    virtual void AdjustForMultInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        OPENFHE_THROW(NOT_SUPPORTED_ERROR);
    }

    /**
     * Wraps a plaintext in a single-element ciphertext that shares the metadata of \p ciphertext
     * (crypto context, key tag) and carries the slots, level, noise scale degree and scaling factors of
     * the plaintext, so that a plaintext operand can go through the ciphertext level/depth adjustment
     * helpers (AdjustForAddOrSubInPlace, AdjustForMultInPlace).
     *
     * @param plaintext the plaintext to wrap.
     * @param ciphertext the ciphertext whose metadata is used for the result.
     * @return a ciphertext with one element holding the plaintext polynomial in EVALUATION format.
     */
    virtual Ciphertext<Element> MorphPlaintext(ConstPlaintext& plaintext, ConstCiphertext<Element>& ciphertext) const;

  protected:
    /////////////////////////////////////////
    // CORE OPERATIONS
    /////////////////////////////////////////
    /**
     * Throws if the two ciphertexts do not have the same number of RNS towers. The trailing
     * CALLER_INFO arguments carry the location of the caller for the error message.
     *
     * @param ciphertext1 first ciphertext.
     * @param ciphertext second ciphertext.
     */
    void VerifyNumOfTowers(ConstCiphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext,
                           CALLER_INFO_ARGS_HDR) const;
    /**
     * Throws if the ciphertext and the plaintext polynomial do not have the same number of RNS towers.
     * The trailing CALLER_INFO arguments carry the location of the caller for the error message.
     *
     * @param ciphertext the ciphertext.
     * @param plaintext the plaintext polynomial.
     */
    void VerifyNumOfTowers(ConstCiphertext<Element>& ciphertext, const Element& plaintext, CALLER_INFO_ARGS_HDR) const;

    /**
     * Internal function for homomorphic addition of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic addition of input ciphertexts.
     */
    virtual Ciphertext<Element> EvalAddCore(ConstCiphertext<Element>& ciphertext1,
                                            ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for in-place homomorphic addition of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input/output ciphertext; on return it contains the
     * result of the homomorphic addition of the input ciphertexts.
     * @param ciphertext2 second input ciphertext.
     */
    void EvalAddCoreInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for homomorphic subtraction of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic subtraction of input ciphertexts.
     */
    virtual Ciphertext<Element> EvalSubCore(ConstCiphertext<Element>& ciphertext1,
                                            ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for in-place homomorphic subtraction of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input/output ciphertext; on return it contains the
     * result of the homomorphic subtraction of the input ciphertexts.
     * @param ciphertext2 second input ciphertext.
     */
    void EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const;

    /**
     * Internal function for homomorphic multiplication of ciphertexts.
     * This method does not check whether input ciphertexts are
     * at the same level.
     *
     * @param ciphertext1 first input ciphertext.
     * @param ciphertext2 second input ciphertext.
     * @return result of homomorphic multiplication of input ciphertexts.
     */
    Ciphertext<Element> EvalMultCore(ConstCiphertext<Element>& ciphertext1,
                                     ConstCiphertext<Element>& ciphertext2) const;
    /**
     * Internal function for multiplication of a ciphertext by a plaintext polynomial: every ciphertext
     * element is multiplied by the polynomial. Only the number of towers is checked; the metadata
     * (scaling factor, noise scale degree) of the result is not updated.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the product ciphertext.
     */
    Ciphertext<Element> EvalMultCore(ConstCiphertext<Element>& ciphertext, const Element& plaintext) const;
    /**
     * Internal in-place multiplication of a ciphertext by a plaintext polynomial; see EvalMultCore.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void EvalMultCoreInPlace(Ciphertext<Element>& ciphertext, const Element& plaintext) const;

    /**
     * Internal function for addition of a plaintext polynomial to a ciphertext: the polynomial is added
     * to the first ciphertext element. Only the number of towers is checked.
     *
     * @param ciphertext the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the sum ciphertext.
     */
    virtual Ciphertext<Element> EvalAddCore(ConstCiphertext<Element>& ciphertext, const Element& plaintext) const;
    /**
     * Internal in-place addition of a plaintext polynomial to the first ciphertext element; see EvalAddCore.
     *
     * @param ciphertext the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void EvalAddCoreInPlace(Ciphertext<Element>& ciphertext, const Element& plaintext) const;

    /**
     * Internal function for subtraction of a plaintext polynomial from a ciphertext: the polynomial is
     * subtracted from the first ciphertext element. Only the number of towers is checked.
     *
     * @param ciphertext1 the input ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     * @return the difference ciphertext.
     */
    virtual Ciphertext<Element> EvalSubCore(ConstCiphertext<Element>& ciphertext1, const Element& plaintext) const;
    /**
     * Internal in-place subtraction of a plaintext polynomial from the first ciphertext element;
     * see EvalSubCore.
     *
     * @param ciphertext1 the input/output ciphertext.
     * @param plaintext the plaintext polynomial (same format and number of towers as the ciphertext).
     */
    void EvalSubCoreInPlace(Ciphertext<Element>& ciphertext1, const Element& plaintext) const;

    /**
     * Internal function for homomorphic squaring of a ciphertext (tensor product with itself, using the
     * symmetry to halve the number of polynomial multiplications). An input with n elements gives a result
     * with 2n-1 elements, doubled noise scale degree and squared scaling factor. This method does not
     * check the level of the input.
     *
     * @param ciphertext the input ciphertext.
     * @return result of homomorphic squaring of the input ciphertext.
     */
    Ciphertext<Element> EvalSquareCore(ConstCiphertext<Element>& ciphertext) const;
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEMEBASE_BASE_LEVELEDSHE_H_
