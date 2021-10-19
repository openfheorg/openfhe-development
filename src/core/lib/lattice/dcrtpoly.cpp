// @file dcrtpoly.cpp - implementation of the integer lattice using double-CRT
// representations.
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

#include <fstream>
#include <memory>

#ifdef WITH_INTEL_HEXL
#include "hexl/hexl.hpp"
#endif

#include "lattice/dcrtpoly.h"
#include "utils/debug.h"

using std::shared_ptr;
using std::string;

namespace lbcrypto {

/*CONSTRUCTORS*/
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl() {
  m_format = Format::EVALUATION;
  m_params = std::make_shared<DCRTPolyImpl::Params>(0, 1);
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const shared_ptr<DCRTPolyImpl::Params> dcrtParams, Format format,
    bool initializeElementToZero) {
  m_format = format;
  m_params = dcrtParams;

  size_t vecSize = dcrtParams->GetParams().size();
  m_vectors.reserve(vecSize);

  for (usint i = 0; i < vecSize; i++) {
    m_vectors.emplace_back(dcrtParams->GetParams()[i], format,
                           initializeElementToZero);
  }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DCRTPolyImpl &element) {
  m_format = element.m_format;
  m_vectors = element.m_vectors;
  m_params = element.m_params;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    const PolyLargeType &element) {
  if (element.GetModulus() > m_params->GetModulus()) {
    PALISADE_THROW(math_error,
                   "Modulus of element passed to constructor is bigger that "
                   "DCRT big modulus");
  }
  m_params->SetOriginalModulus(element.GetModulus());

  size_t vecCount = m_params->GetParams().size();
  m_vectors.clear();
  m_vectors.reserve(vecCount);

  // fill up with vectors with the proper moduli
  for (usint i = 0; i < vecCount; i++) {
    PolyType newvec(m_params->GetParams()[i], m_format, true);
    m_vectors.push_back(std::move(newvec));
  }

  // need big ints out of the little ints for the modulo operations, below
  std::vector<Integer> bigmods;
  bigmods.reserve(vecCount);
  for (usint i = 0; i < vecCount; i++)
    bigmods.push_back(
        Integer(m_params->GetParams()[i]->GetModulus().ConvertToInt()));

  // copy each coefficient mod the new modulus
  for (usint p = 0; p < element.GetLength(); p++) {
    for (usint v = 0; v < vecCount; v++) {
      Integer tmp = element.at(p) % bigmods[v];
      m_vectors[v].at(p) = tmp.ConvertToInt();
    }
  }

  return *this;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    const NativePoly &element) {
  if (typename Params::Integer(element.GetModulus()) > m_params->GetModulus()) {
    PALISADE_THROW(math_error,
                   "Modulus of element passed to constructor is bigger that "
                   "DCRT big modulus");
  }

  size_t vecCount = m_params->GetParams().size();
  m_vectors.clear();
  m_vectors.reserve(vecCount);

  // fill up with vectors with the proper moduli
  for (usint i = 0; i < vecCount; i++) {
    PolyType newvec(element);
    if (i > 0) {
      newvec.SwitchModulus(m_params->GetParams()[i]->GetModulus(),
                           m_params->GetParams()[i]->GetRootOfUnity());
    }
    m_vectors.push_back(std::move(newvec));
  }

  return *this;
}

/* Construct from a single Poly. The format  is derived from the passed in
 * Poly.*/
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const PolyLargeType &element,
    const shared_ptr<DCRTPolyImpl::Params> params) {
  Format format;
  try {
    format = element.GetFormat();
  } catch (const std::exception &e) {
    PALISADE_THROW(type_error,
                   "There is an issue with the format of the Poly passed to "
                   "the constructor of DCRTPolyImpl");
  }

  if (element.GetCyclotomicOrder() != params->GetCyclotomicOrder()) {
    PALISADE_THROW(math_error,
                   "Cyclotomic order mismatch on input vector and parameters");
  }

  m_format = format;
  m_params = params;
  m_params->SetOriginalModulus(element.GetModulus());

  *this = element;
}

/* Construct from a single Poly. The format is derived from the passed in
 * Poly.*/
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const NativePoly &element, const shared_ptr<DCRTPolyImpl::Params> params) {
  Format format;
  try {
    format = element.GetFormat();
  } catch (const std::exception &e) {
    PALISADE_THROW(type_error,
                   "There is an issue with the format of the NativePoly passed "
                   "to the constructor of DCRTPolyImpl");
  }

  if (element.GetCyclotomicOrder() != params->GetCyclotomicOrder())
    PALISADE_THROW(math_error,
                   "Cyclotomic order mismatch on input vector and parameters");

  m_format = format;
  m_params = params;

  *this = element;
}

/* Construct using a tower of vectors.
 * The params and format for the DCRTPolyImpl will be derived from the towers
 */
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const std::vector<PolyType> &towers) {
  usint cyclotomicOrder = towers.at(0).GetCyclotomicOrder();
  std::vector<std::shared_ptr<ILNativeParams>> parms;
  for (usint i = 0; i < towers.size(); i++) {
    if (towers[i].GetCyclotomicOrder() != cyclotomicOrder) {
      PALISADE_THROW(
          math_error,
          "Polys provided to constructor must have the same ring dimension");
    }
    parms.push_back(towers[i].GetParams());
  }
  m_params = std::make_shared<DCRTPolyImpl::Params>(cyclotomicOrder, parms);
  m_vectors = towers;
  m_format = m_vectors[0].GetFormat();
}

/*The dgg will be the seed to populate the towers of the DCRTPolyImpl with
 * random numbers. The algorithm to populate the towers can be seen below.*/
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const DggType &dgg, const shared_ptr<DCRTPolyImpl::Params> dcrtParams,
    Format format) {
  m_format = format;
  m_params = dcrtParams;

  size_t vecSize = dcrtParams->GetParams().size();
  m_vectors.reserve(vecSize);

  // dgg generating random values
  std::shared_ptr<int64_t> dggValues =
      dgg.GenerateIntVector(dcrtParams->GetRingDimension());

  for (usint i = 0; i < vecSize; i++) {
    NativeVector ilDggValues(dcrtParams->GetRingDimension(),
                             dcrtParams->GetParams()[i]->GetModulus());

    for (usint j = 0; j < dcrtParams->GetRingDimension(); j++) {
      NativeInteger::Integer entry;
      // if the random generated value is less than zero, then multiply it by
      // (-1) and subtract the modulus of the current tower to set the
      // coefficient
      NativeInteger::SignedNativeInt k = (dggValues.get())[j];
      auto dcrt_qmodulus = (NativeInteger::SignedNativeInt)dcrtParams->GetParams()[i]
                    ->GetModulus()
                    .ConvertToInt();
      auto dgg_stddev = dgg.GetStd();
 
      if (dgg_stddev > dcrt_qmodulus) {
        //rescale k to dcrt_qmodulus
        auto mk = k % dcrt_qmodulus;
        k = (NativeInteger::Integer)mk;
      }
      if (k < 0) {
        k *= (-1);
        entry = (NativeInteger::Integer)dcrtParams->GetParams()[i]
                    ->GetModulus()
                    .ConvertToInt() -
                (NativeInteger::Integer)k;
      } else {  // if greater than or equal to zero, set it the value generated
        entry = k;
      }
      ilDggValues.at(j) = entry;
    }

    PolyType ilvector(dcrtParams->GetParams()[i]);
    // the random values are set in coefficient format
    ilvector.SetValues(std::move(ilDggValues), Format::COEFFICIENT);
    // set the format to what the caller asked for.
    ilvector.SetFormat(m_format);
    m_vectors.push_back(std::move(ilvector));
  }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    DugType &dug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams,
    Format format) {
  m_format = format;
  m_params = dcrtParams;

  size_t numberOfTowers = dcrtParams->GetParams().size();
  m_vectors.reserve(numberOfTowers);

  for (usint i = 0; i < numberOfTowers; i++) {
    dug.SetModulus(dcrtParams->GetParams()[i]->GetModulus());
    NativeVector vals(dug.GenerateVector(dcrtParams->GetRingDimension()));

    PolyType ilvector(dcrtParams->GetParams()[i]);

    // the random values are set in coefficient format
    ilvector.SetValues(std::move(vals), Format::COEFFICIENT);
    // set the format to what the caller asked for.
    ilvector.SetFormat(m_format);
    m_vectors.push_back(std::move(ilvector));
  }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const BugType &bug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams,
    Format format) {
  m_format = format;
  m_params = dcrtParams;

  size_t numberOfTowers = dcrtParams->GetParams().size();
  m_vectors.reserve(numberOfTowers);

  PolyType ilvector(bug, dcrtParams->GetParams()[0], COEFFICIENT);

  for (usint i = 0; i < numberOfTowers; i++) {
    if (i > 0)
      ilvector.SwitchModulus(dcrtParams->GetParams()[i]->GetModulus(),
                             dcrtParams->GetParams()[i]->GetRootOfUnity());

    auto newVector = ilvector;
    // set the format to what the caller asked for.
    newVector.SetFormat(m_format);
    m_vectors.push_back(std::move(newVector));
  }
}

template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(
    const TugType &tug, const shared_ptr<DCRTPolyImpl::Params> dcrtParams,
    Format format, uint32_t h) {
  m_format = format;
  m_params = dcrtParams;

  size_t numberOfTowers = dcrtParams->GetParams().size();
  m_vectors.reserve(numberOfTowers);

  // tug generating random values
  std::shared_ptr<int32_t> tugValues =
      tug.GenerateIntVector(dcrtParams->GetRingDimension(), h);

  for (usint i = 0; i < numberOfTowers; i++) {
    NativeVector ilTugValues(dcrtParams->GetRingDimension(),
                             dcrtParams->GetParams()[i]->GetModulus());

    for (usint j = 0; j < dcrtParams->GetRingDimension(); j++) {
      NativeInteger::Integer entry;
      // if the random generated value is less than zero, then multiply it by
      // (-1) and subtract the modulus of the current tower to set the
      // coefficient
      NativeInteger::SignedNativeInt k = (tugValues.get())[j];
      if (k < 0) {
        k *= (-1);
        entry = (NativeInteger::Integer)dcrtParams->GetParams()[i]
                    ->GetModulus()
                    .ConvertToInt() -
                (NativeInteger::Integer)k;
      } else {  // if greater than or equal to zero, set it the value generated
        entry = k;
      }
      ilTugValues.at(j) = entry;
    }

    PolyType ilvector(dcrtParams->GetParams()[i]);
    // the random values are set in coefficient format
    ilvector.SetValues(std::move(ilTugValues), Format::COEFFICIENT);
    // set the format to what the caller asked for.
    ilvector.SetFormat(m_format);
    m_vectors.push_back(std::move(ilvector));
  }
}

/*Move constructor*/
template <typename VecType>
DCRTPolyImpl<VecType>::DCRTPolyImpl(const DCRTPolyImpl &&element) {
  m_format = element.m_format;
  m_vectors = std::move(element.m_vectors);
  m_params = std::move(element.m_params);
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneParametersOnly() const {
  DCRTPolyImpl res(this->m_params, this->m_format);
  return res;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::CloneWithNoise(
    const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const {
  DCRTPolyImpl res = CloneParametersOnly();

  VecType randVec = dgg.GenerateVector(m_params->GetCyclotomicOrder() / 2,
                                       m_params->GetModulus());

  // create an Element to pull from
  // create a dummy parm to use in the Poly world
  auto parm = std::make_shared<ILParamsImpl<Integer>>(
      m_params->GetCyclotomicOrder(), m_params->GetModulus(), 1);
  PolyLargeType element(parm);
  element.SetValues(std::move(randVec), m_format);

  res = element;

  return res;
}

// DESTRUCTORS

template <typename VecType>
DCRTPolyImpl<VecType>::~DCRTPolyImpl() {}

// GET ACCESSORS
template <typename VecType>
const typename DCRTPolyImpl<VecType>::PolyType &
DCRTPolyImpl<VecType>::GetElementAtIndex(usint i) const {
  if (m_vectors.empty())
    PALISADE_THROW(config_error, "DCRTPolyImpl's towers are not initialized.");
  if (i > m_vectors.size() - 1)
    PALISADE_THROW(math_error, "Index: " + std::to_string(i) +
                                   " is out of range for vector of size " +
                                   std::to_string(m_vectors.size()) + ".");
  return m_vectors[i];
}

template <typename VecType>
usint DCRTPolyImpl<VecType>::GetNumOfElements() const {
  return m_vectors.size();
}

template <typename VecType>
const std::vector<typename DCRTPolyImpl<VecType>::PolyType>
    &DCRTPolyImpl<VecType>::GetAllElements() const {
  return m_vectors;
}

template <typename VecType>
Format DCRTPolyImpl<VecType>::GetFormat() const {
  return m_format;
}

template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::BaseDecompose(
    usint baseBits, bool evalModeAnswer) const {
  DEBUG_FLAG(false);
  DEBUG("...::BaseDecompose");
  DEBUG("baseBits=" << baseBits);

  PolyLargeType v(CRTInterpolate());

  DEBUG("<v>" << std::endl << v << "</v>");

  std::vector<PolyLargeType> bdV = v.BaseDecompose(baseBits, false);

#if !defined(NDEBUG)
  DEBUG("<bdV>");
  for (auto i : bdV) DEBUG(i);
  DEBUG("</bdV>");
#endif

  std::vector<DCRTPolyImpl<VecType>> result;
  result.reserve(bdV.size());

  // populate the result by converting each of the big vectors into a
  // VectorArray
  for (usint i = 0; i < bdV.size(); i++) {
    DCRTPolyImpl<VecType> dv(bdV[i], this->GetParams());
    if (evalModeAnswer) dv.SwitchFormat();
    result.push_back(std::move(dv));
  }

#if !defined(NDEBUG)
  DEBUG("<BaseDecompose.result>");
  for (auto i : result) DEBUG(i);
  DEBUG("</BaseDecompose.result>");
#endif

  return result;
}

template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::CRTDecompose(
    uint32_t baseBits) const {
  uint32_t nWindows = 0;

  // used to store the number of digits for each small modulus
  std::vector<usint> arrWindows;

  if (baseBits > 0) {
    nWindows = 0;

    // creates an array of digits up to a certain tower
    for (usint i = 0; i < m_vectors.size(); i++) {
      usint nBits = m_vectors[i].GetModulus().GetLengthForBase(2);
      usint curWindows = nBits / baseBits;
      if (nBits % baseBits > 0) curWindows++;
      arrWindows.push_back(nWindows);
      nWindows += curWindows;
    }

  } else {
    nWindows = m_vectors.size();
  }

  std::vector<DCRTPolyType> result(nWindows);

  DCRTPolyType input = this->Clone();
  input.SetFormat(Format::COEFFICIENT);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    if (baseBits == 0) {
      DCRTPolyType currentDCRTPoly = input.Clone();

      for (usint k = 0; k < m_vectors.size(); k++) {
        PolyType temp(input.m_vectors[i]);
        if (i != k) {
          temp.SwitchModulus(input.m_vectors[k].GetModulus(),
                             input.m_vectors[k].GetRootOfUnity());
          temp.SetFormat(Format::EVALUATION);
          currentDCRTPoly.m_vectors[k] = std::move(temp);
        } else {  // saves an extra NTT
          currentDCRTPoly.m_vectors[k] = this->m_vectors[k];
          currentDCRTPoly.m_vectors[k].SetFormat(Format::EVALUATION);
        }
      }

      currentDCRTPoly.m_format = Format::EVALUATION;

      result[i] = std::move(currentDCRTPoly);
    } else {
      vector<PolyType> decomposed =
          input.m_vectors[i].BaseDecompose(baseBits, false);

      for (size_t j = 0; j < decomposed.size(); j++) {
        DCRTPolyType currentDCRTPoly = input.Clone();

        for (usint k = 0; k < m_vectors.size(); k++) {
          PolyType temp(decomposed[j]);
          if (i != k)
            temp.SwitchModulus(input.m_vectors[k].GetModulus(),
                               input.m_vectors[k].GetRootOfUnity());
          currentDCRTPoly.m_vectors[k] = std::move(temp);
        }

        currentDCRTPoly.SwitchFormat();

        result[j + arrWindows[i]] = std::move(currentDCRTPoly);
      }
    }
  }

  return result;
}

template <typename VecType>
PolyImpl<NativeVector> &DCRTPolyImpl<VecType>::ElementAtIndex(usint i) {
  return m_vectors[i];
}

template <typename VecType>
std::vector<DCRTPolyImpl<VecType>> DCRTPolyImpl<VecType>::PowersOfBase(
    usint baseBits) const {
  DEBUG_FLAG(false);

  std::vector<DCRTPolyImpl<VecType>> result;

  usint nBits = m_params->GetModulus().GetLengthForBase(2);

  usint nWindows = nBits / baseBits;
  if (nBits % baseBits > 0) nWindows++;

  result.reserve(nWindows);

  // prepare for the calculations by gathering a big integer version of each of
  // the little moduli
  std::vector<Integer> mods(m_params->GetParams().size());
  for (usint i = 0; i < m_params->GetParams().size(); i++) {
    mods[i] = Integer(m_params->GetParams()[i]->GetModulus().ConvertToInt());
    DEBUG("DCRTPolyImpl::PowersOfBase.mods[" << i << "] = " << mods[i]);
  }

  for (usint i = 0; i < nWindows; i++) {
    DCRTPolyType x(m_params, m_format);

    // Shouldn't this be Integer twoPow ( Integer::ONE << (i*baseBits)  ??
    Integer twoPow(Integer(2).Exp(i * baseBits));
    DEBUG("DCRTPolyImpl::PowersOfBase.twoPow (" << i << ") = " << twoPow);
    for (usint t = 0; t < m_params->GetParams().size(); t++) {
      DEBUG("@(" << i << ", " << t << ")");
      DEBUG("twoPow= " << twoPow << ", mods[" << t << "]" << mods[t]);
      Integer pI(twoPow % mods[t]);
      DEBUG("twoPow= " << twoPow << ", mods[" << t << "]" << mods[t]
                       << ";   pI.ConvertToInt="
                       << NativeInteger(pI.ConvertToInt()) << ";   pI=" << pI);
      DEBUG("m_vectors= " << m_vectors[t]);

      x.m_vectors[t] = m_vectors[t] * pI.ConvertToInt();
      DEBUG("DCRTPolyImpl::PowersOfBase.x.m_vectors[" << t << ", " << i << "]"
                                                      << x.m_vectors[t]);
    }
    result.push_back(std::move(x));
  }

  return result;
}

/*VECTOR OPERATIONS*/

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::MultiplicativeInverse() const {
  DCRTPolyImpl<VecType> tmp(*this);

  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ModByTwo() const {
  DCRTPolyImpl<VecType> tmp(*this);

  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] = m_vectors[i].ModByTwo();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(
    const DCRTPolyImpl &element) const {
  if (m_vectors.size() != element.m_vectors.size()) {
    PALISADE_THROW(math_error, "tower size mismatch; cannot add");
  }
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] += element.GetElementAtIndex(i);
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Negate() const {
  DCRTPolyImpl<VecType> tmp(this->CloneParametersOnly());
  tmp.m_vectors.clear();

  for (usint i = 0; i < this->m_vectors.size(); i++) {
    tmp.m_vectors.push_back(std::move(this->m_vectors.at(i).Negate()));
  }

  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(
    const DCRTPolyImpl &element) const {
  if (m_vectors.size() != element.m_vectors.size()) {
    PALISADE_THROW(math_error, "tower size mismatch; cannot subtract");
  }
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] -= element.GetElementAtIndex(i);
  }
  return tmp;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator+=(
    const DCRTPolyImpl &rhs) {
#pragma omp parallel for
  for (usint i = 0; i < this->GetNumOfElements(); i++) {
    this->m_vectors[i] += rhs.m_vectors[i];
  }
  return *this;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator-=(
    const DCRTPolyImpl &rhs) {
#pragma omp parallel for
  for (usint i = 0; i < this->GetNumOfElements(); i++) {
    this->m_vectors.at(i) -= rhs.m_vectors[i];
  }
  return *this;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator*=(
    const DCRTPolyImpl &element) {
#pragma omp parallel for
  for (usint i = 0; i < this->m_vectors.size(); i++) {
    this->m_vectors.at(i) *= element.m_vectors.at(i);
  }

  return *this;
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::operator==(const DCRTPolyImpl &rhs) const {
  if (GetCyclotomicOrder() != rhs.GetCyclotomicOrder()) return false;

  if (GetModulus() != rhs.GetModulus()) return false;

  if (m_format != rhs.m_format) {
    return false;
  }

  if (m_vectors.size() != rhs.m_vectors.size()) {
    return false;
  }
  // check if the towers are the same
  return (m_vectors == rhs.GetAllElements());
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    const DCRTPolyImpl &rhs) {
  if (this != &rhs) {
    m_vectors = rhs.m_vectors;
    m_format = rhs.m_format;
    m_params = rhs.m_params;
  }
  return *this;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    DCRTPolyImpl &&rhs) {
  if (this != &rhs) {
    m_vectors = std::move(rhs.m_vectors);
    m_format = std::move(rhs.m_format);
    m_params = std::move(rhs.m_params);
  }
  return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    std::initializer_list<uint64_t> rhs) {
  DEBUG_FLAG(false);
  usint len = rhs.size();
  static PolyType::Integer ZERO(0);
  if (!IsEmpty()) {
    usint vectorLength = this->m_vectors[0].GetLength();
    DEBUGEXP(vectorLength);
    for (usint i = 0; i < m_vectors.size();
         ++i) {                                   // this loops over each tower
      for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
        if (j < len) {
          this->m_vectors[i].at(j) = PolyType::Integer(*(rhs.begin() + j));
          DEBUGEXP(this->m_vectors[i].at(j));
        } else {
          this->m_vectors[i].at(j) = ZERO;
          DEBUGEXP(ZERO);
        }
      }
    }
  } else {
    DEBUGEXP(m_vectors.size());
    for (size_t i = 0; i < m_vectors.size(); i++) {
      NativeVector temp(m_params->GetRingDimension());
      temp.SetModulus(m_vectors.at(i).GetModulus());
      temp = rhs;
      m_vectors.at(i).SetValues(std::move(temp), m_format);
    }
  }
  return *this;
}

#if 1
template <typename VecType>
DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    std::initializer_list<std::string> rhs) {
  DEBUG_FLAG(false);
  usint len = rhs.size();
  static PolyType::Integer ZERO(0);
  if (!IsEmpty()) {
    usint vectorLength = this->m_vectors[0].GetLength();
    DEBUGEXP(vectorLength);
    for (usint i = 0; i < m_vectors.size();
         ++i) {                                   // this loops over each tower
      for (usint j = 0; j < vectorLength; ++j) {  // loops within a tower
        DEBUGEXP(j);
        if (j < len) {
          this->m_vectors[i].at(j) = PolyType::Integer(*(rhs.begin() + j));
          DEBUGEXP(this->m_vectors[i].at(j));
        } else {
          this->m_vectors[i].at(j) = ZERO;
          DEBUGEXP(ZERO);
        }
      }
    }
  } else {
    DEBUGEXP(m_vectors.size());
    for (size_t i = 0; i < m_vectors.size(); i++) {
      NativeVector temp(m_params->GetRingDimension());
      temp.SetModulus(m_vectors.at(i).GetModulus());
      temp = rhs;
      m_vectors.at(i).SetValues(std::move(temp), m_format);
    }
  }
  return *this;
}
#endif
// Used only inside a Matrix object; so an allocator already initializes the
// values
template <typename VecType>
DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(uint64_t val) {
  if (!IsEmpty()) {
    for (usint i = 0; i < m_vectors.size(); i++) {
      m_vectors[i] = val;
    }
  } else {
    for (usint i = 0; i < m_vectors.size(); i++) {
      NativeVector temp(m_params->GetRingDimension());
      temp.SetModulus(m_vectors.at(i).GetModulus());
      temp = val;
      m_vectors.at(i).SetValues(std::move(temp), m_format);
    }
  }

  return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the
// values
template <typename VecType>
DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    const std::vector<int64_t> &val) {
  if (!IsEmpty()) {
    for (usint i = 0; i < m_vectors.size(); i++) {
      m_vectors[i] = val;
    }
  } else {
    for (usint i = 0; i < m_vectors.size(); i++) {
      NativeVector temp(m_params->GetRingDimension());
      temp.SetModulus(m_vectors.at(i).GetModulus());
      m_vectors.at(i).SetValues(std::move(temp), m_format);
      m_vectors[i] = val;
    }
  }

  m_format = COEFFICIENT;

  return *this;
}

// Used only inside a Matrix object; so an allocator already initializes the
// values
template <typename VecType>
DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator=(
    const std::vector<int32_t> &val) {
  if (!IsEmpty()) {
    for (usint i = 0; i < m_vectors.size(); i++) {
      m_vectors[i] = val;
    }
  } else {
    for (usint i = 0; i < m_vectors.size(); i++) {
      NativeVector temp(m_params->GetRingDimension());
      temp.SetModulus(m_vectors.at(i).GetModulus());
      m_vectors.at(i).SetValues(std::move(temp), m_format);
      m_vectors[i] = val;
    }
  }

  m_format = COEFFICIENT;

  return *this;
}

/*SCALAR OPERATIONS*/

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(
    const Integer &element) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] += element.ConvertToInt();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Plus(
    const vector<Integer> &crtElement) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] += crtElement[i].ConvertToInt();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(
    const Integer &element) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] -= element.ConvertToInt();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Minus(
    const vector<Integer> &crtElement) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < tmp.m_vectors.size(); i++) {
    tmp.m_vectors[i] -= crtElement[i].ConvertToInt();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
    const DCRTPolyImpl &element) const {
  if (m_vectors.size() != element.m_vectors.size()) {
    PALISADE_THROW(math_error, "tower size mismatch; cannot multiply");
  }
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    // ModMul multiplies and performs a mod operation on the results. The mod is
    // the modulus of each tower.
    tmp.m_vectors[i] *= element.m_vectors[i];
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
    const Integer &element) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] =
        tmp.m_vectors[i] *
        element
            .ConvertToInt();  // (element %
                              // Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
    bigintnat::NativeInteger::SignedNativeInt element) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] = tmp.m_vectors[i].Times(element);
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
    const std::vector<Integer> &crtElement) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] =
        this->m_vectors[i].Times(NativeInteger(crtElement[i].ConvertToInt()));
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(
    const std::vector<NativeInteger> &element) const {
  DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    tmp.m_vectors[i] *= element[i];
  }
  return tmp;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::MultiplyAndRound(
    const Integer &p, const Integer &q) const {
  std::string errMsg = "Operation not implemented yet";
  PALISADE_THROW(not_implemented_error, errMsg);
  return *this;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::DivideAndRound(
    const Integer &q) const {
  std::string errMsg = "Operation not implemented yet";
  PALISADE_THROW(not_implemented_error, errMsg);
  return *this;
}

template <typename VecType>
const DCRTPolyImpl<VecType> &DCRTPolyImpl<VecType>::operator*=(
    const Integer &element) {
  for (usint i = 0; i < this->m_vectors.size(); i++) {
    this->m_vectors.at(i) *=
        (element.Mod(this->m_vectors[i].GetModulus())).ConvertToInt();
  }

  return *this;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::SetValuesToZero() {
  for (usint i = 0; i < m_vectors.size(); i++) {
    m_vectors[i].SetValuesToZero();
  }
}
/*OTHER FUNCTIONS*/

template <typename VecType>
void DCRTPolyImpl<VecType>::AddILElementOne() {
  if (m_format != Format::EVALUATION)
    PALISADE_THROW(not_available_error,
                   "DCRTPolyImpl<VecType>::AddILElementOne cannot be called on "
                   "a DCRTPolyImpl in COEFFICIENT format.");
  for (usint i = 0; i < m_vectors.size(); i++) {
    m_vectors[i].AddILElementOne();
  }
}

template <typename VecType>
void DCRTPolyImpl<VecType>::MakeSparse(const uint32_t &wFactor) {
  for (usint i = 0; i < m_vectors.size(); i++) {
    m_vectors[i].MakeSparse(wFactor);
  }
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::IsEmpty() const {
  for (size_t i = 0; i < m_vectors.size(); i++) {
    if (!m_vectors.at(i).IsEmpty()) return false;
  }
  return true;
}

template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElement() {
  if (m_vectors.size() == 0) {
    PALISADE_THROW(math_error, "Last element being removed from empty list");
  }
  m_vectors.resize(m_vectors.size() - 1);

  DCRTPolyImpl::Params *newP = new DCRTPolyImpl::Params(*m_params);
  newP->PopLastParam();
  m_params.reset(newP);
}

template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElements(size_t i) {
  if (m_vectors.size() < i) {
    PALISADE_THROW(config_error,
                   "There are not enough towers in the current ciphertext to "
                   "perform the modulus reduction");
  }

  m_vectors.resize(m_vectors.size() - i);
  DCRTPolyImpl::Params *newP = new DCRTPolyImpl::Params(*m_params);
  for (size_t j = 0; j < i; j++) newP->PopLastParam();
  m_params.reset(newP);
}

// used for CKKS rescaling
template <typename VecType>
void DCRTPolyImpl<VecType>::DropLastElementAndScale(
    const std::vector<NativeInteger> &QlQlInvModqlDivqlModq,
    const std::vector<NativeInteger> &QlQlInvModqlDivqlModqPrecon,
    const std::vector<NativeInteger> &qlInvModq,
    const std::vector<NativeInteger> &qlInvModqPrecon) {
  usint sizeQl = m_vectors.size();

  // last tower that will be dropped
  PolyType lastPoly(m_vectors[sizeQl - 1]);

  // drop the last tower
  DropLastElement();

  lastPoly.SetFormat(Format::COEFFICIENT);
  DCRTPolyType extra(m_params, COEFFICIENT, true);

#pragma omp parallel for
  for (usint i = 0; i < extra.m_vectors.size(); i++) {
    auto temp = lastPoly;
    temp.SwitchModulus(m_vectors[i].GetModulus(),
                       m_vectors[i].GetRootOfUnity());
    extra.m_vectors[i] = (temp *= QlQlInvModqlDivqlModq[i]);
  }

  if (this->GetFormat() == Format::EVALUATION)
    extra.SetFormat(Format::EVALUATION);

#ifdef WITH_INTEL_HEXL
  usint ringDim = GetRingDimension();
  for (usint i = 0; i < m_vectors.size(); i++) {
    const NativeInteger &qi = m_vectors[i].GetModulus();
    PolyType &m_veci = m_vectors[i];
    PolyType &extra_m_veci = extra.m_vectors[i];
    const auto multOp = qlInvModq[i];
    uint64_t *op1 = reinterpret_cast<uint64_t *>(&m_veci[0]);
    uint64_t op2 = multOp.ConvertToInt();
    uint64_t *op3 = reinterpret_cast<uint64_t *>(&extra_m_veci[0]);
    intel::hexl::EltwiseFMAMod(op1, op1, op2, op3, ringDim, qi.ConvertToInt(),
                               1);
  }
#else
#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    m_vectors[i] *= qlInvModq[i];
    m_vectors[i] += extra.m_vectors[i];
  }
#endif

  this->SetFormat(Format::EVALUATION);
}

/**
* Used for BGVrns modulus switching
* This function performs ModReduce on ciphertext element and private key
element. The algorithm computes ct' <- round( ct/qt ).

* Modulus reduction reduces a ciphertext from modulus q to a smaller modulus
q/qt where qt is generally the last moduli of the tower.
* ModReduce is written for DCRTPolyImpl and it drops the last tower while
updating the necessary parameters.

* The rounding is actually computed as a flooring by computing delta such that
delta = -ct mod qt and delta = 0 [t]

* The steps taken here are as follows:
* 1. compute delta <- -ct/ptm mod qt
* 2. compute delta <- ptm*delta in Z. E.g., all of delta's integer coefficients
can be in the range [-ptm*qt/2, ptm*qt/2).
* 3. let d' = c + delta mod q/qt. By construction, d' is divisible by qt and
congruent to 0 mod ptm.
* 4. output (d'/q') in R(q/q').
*/
template <typename VecType>
void DCRTPolyImpl<VecType>::ModReduce(
    const NativeInteger &t, const std::vector<NativeInteger> &tModqPrecon,
    const NativeInteger &negtInvModq, const NativeInteger &negtInvModqPrecon,
    const std::vector<NativeInteger> &qlInvModq,
    const std::vector<NativeInteger> &qlInvModqPrecon) {
  usint sizeQl = m_vectors.size();

  // last tower that will be dropped
  PolyType delta(m_vectors[sizeQl - 1]);

  // Pull tower to be dropped in COEFFICIENT FORMAT
  delta.SetFormat(Format::COEFFICIENT);

  DropLastElement();

  if (m_format == Format::EVALUATION) {
    DCRTPolyType extra(m_params, COEFFICIENT, true);

    delta *= negtInvModq;

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
      auto temp = delta;
      temp.SwitchModulus(m_vectors[i].GetModulus(),
                         m_vectors[i].GetRootOfUnity());
      extra.m_vectors[i] = temp;
    }

    extra.SetFormat(Format::EVALUATION);

#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
      extra.m_vectors[i] *= t;
      m_vectors[i] += extra.m_vectors[i];
      m_vectors[i] *= qlInvModq[i];
    }

  } else {
    delta *= negtInvModq;
#pragma omp parallel for
    for (usint i = 0; i < m_vectors.size(); i++) {
      auto temp = delta;
      temp.SwitchModulus(m_vectors[i].GetModulus(),
                         m_vectors[i].GetRootOfUnity());
      m_vectors[i] += (temp *= t);
      m_vectors[i] *= qlInvModq[i];
    }
  }
}

/* methods to access individual members of the DCRTPolyImpl. Result is
 * Interpolated value at that point.  Note this is a very costly compute
 * intensive operation meant basically for debugging code.
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::Integer &DCRTPolyImpl<VecType>::at(usint i) {
  if (m_vectors.size() == 0)
    PALISADE_THROW(math_error, "No values in DCRTPolyImpl");
  if (i >= GetLength())
    PALISADE_THROW(math_error, "out of range in  DCRTPolyImpl.at()");
  PolyLargeType tmp(CRTInterpolateIndex(i));
  return tmp[i];
}

template <typename VecType>
const typename DCRTPolyImpl<VecType>::Integer &DCRTPolyImpl<VecType>::at(
    usint i) const {
  if (m_vectors.size() == 0)
    PALISADE_THROW(math_error, "No values in DCRTPolyImpl");
  if (i >= GetLength())
    PALISADE_THROW(math_error, "out of range in  DCRTPolyImpl.at()");
  PolyLargeType tmp(CRTInterpolateIndex(i));
  return tmp[i];
}

template <typename VecType>
typename DCRTPolyImpl<VecType>::Integer &DCRTPolyImpl<VecType>::operator[](
    usint i) {
  PolyLargeType tmp(CRTInterpolateIndex(i));
  return tmp[i];
}

template <typename VecType>
const typename DCRTPolyImpl<VecType>::Integer
    &DCRTPolyImpl<VecType>::operator[](usint i) const {
  PolyLargeType tmp(CRTInterpolateIndex(i));
  return tmp[i];
}

/*
 * This method applies the Chinese Remainder Interpolation on an DCRTPolyImpl
 * and produces an Poly How the Algorithm works: Consider the DCRTPolyImpl as
 * a 2-dimensional matrix M, with dimension ringDimension * Number of Towers.
 * For brevity , lets say this is r * t Let qt denote the bigModulus (all the
 * towers' moduli multiplied together) and qi denote the modulus of a
 * particular tower. Let V be a BigVector of size tower (tower size). Each
 * coefficient of V is calculated as follows: for every r calculate: V[j]=
 * {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[ (qt/qi)^(-1) mod qi ]}mod
 * qt
 *
 * Once we have the V values, we construct an Poly from V, use qt as it's
 * modulus, and calculate a root of unity for parameter selection of the Poly.
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType
DCRTPolyImpl<VecType>::CRTInterpolate() const {
  DEBUG_FLAG(false);

  usint ringDimension = GetRingDimension();
  usint nTowers = m_vectors.size();

  DEBUG("in Interpolate ring " << ringDimension << " towers " << nTowers);

  for (usint vi = 0; vi < nTowers; vi++)
    DEBUG("tower " << vi << " is " << m_vectors[vi]);

  Integer bigModulus(GetModulus());  // qT

  DEBUG("bigModulus " << bigModulus);

  // this is the resulting vector of coefficients
  VecType coefficients(ringDimension, bigModulus);

  // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj
  // *[ (qt/qj)^(-1) mod qj ]}modqt

  // first, precompute qt/qj factors
  vector<Integer> multiplier(nTowers);
  for (usint vi = 0; vi < nTowers; vi++) {
    Integer qj(m_vectors[vi].GetModulus().ConvertToInt());
    Integer divBy = bigModulus / qj;
    Integer modInv = divBy.ModInverse(qj).Mod(qj);
    multiplier[vi] = divBy * modInv;

    DEBUG("multiplier " << vi << " " << qj << " " << multiplier[vi]);
  }

  // if the vectors are not in COEFFICIENT form, they need to be, so we will
  // need to make a copy of them and switchformat on them... otherwise we can
  // just use what we have
  const std::vector<PolyType> *vecs = &m_vectors;
  std::vector<PolyType> coeffVecs;
  if (m_format == Format::EVALUATION) {
    for (usint i = 0; i < m_vectors.size(); i++) {
      PolyType vecCopy(m_vectors[i]);
      vecCopy.SetFormat(Format::COEFFICIENT);
      coeffVecs.push_back(std::move(vecCopy));
    }
    vecs = std::move(&coeffVecs);
  }

  for (usint vi = 0; vi < nTowers; vi++)
    DEBUG("tower " << vi << " is " << (*vecs)[vi]);

  // Precompute the Barrett mu parameter
  Integer mu = bigModulus.ComputeMu();

  // now, compute the values for the vector
#pragma omp parallel for
  for (usint ri = 0; ri < ringDimension; ri++) {
    coefficients[ri] = 0;
    for (usint vi = 0; vi < nTowers; vi++) {
      coefficients[ri] += (Integer((*vecs)[vi].GetValues()[ri].ConvertToInt()) *
                           multiplier[vi]);
    }
    DEBUG((*vecs)[0].GetValues()[ri] << " * " << multiplier[0]
                                     << " == " << coefficients[ri]);
    coefficients[ri].ModEq(bigModulus, mu);
  }

  DEBUG("passed loops");
  DEBUG(coefficients);

  // Create an Poly for this BigVector

  DEBUG("elementing after vectoring");
  DEBUG("m_cyclotomicOrder " << GetCyclotomicOrder());
  DEBUG("modulus " << bigModulus);

  // Setting the root of unity to ONE as the calculation is expensive and not
  // required.
  typename DCRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed(
      std::make_shared<ILParamsImpl<Integer>>(GetCyclotomicOrder(), bigModulus,
                                              1));
  polynomialReconstructed.SetValues(std::move(coefficients), COEFFICIENT);

  DEBUG("answer: " << polynomialReconstructed);

  return polynomialReconstructed;
}

/*
 * This method applies the Chinese Remainder Interpolation on a
 * single element across all towers of a DCRTPolyImpl and produces an Poly
 * with zeros except at that single element
 * How the Algorithm works:
 * Consider the DCRTPolyImpl as a 2-dimensional matrix M, with dimension
 * ringDimension * Number of Towers. For brevity , lets say this is r * t Let
 * qt denote the bigModulus (all the towers' moduli multiplied together) and
 * qi denote the modulus of a particular tower. Let V be a BigVector of size
 * tower (tower size). Each coefficient of V is calculated as follows: for
 * every r calculate: V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qi *[
 * (qt/qi)^(-1) mod qi ]}mod qt
 *
 * Once we have the V values, we construct an Poly from V, use qt as it's
 * modulus, and calculate a root of unity for parameter selection of the Poly.
 */
template <typename VecType>
typename DCRTPolyImpl<VecType>::PolyLargeType
DCRTPolyImpl<VecType>::CRTInterpolateIndex(usint i) const {
  DEBUG_FLAG(false);

  usint ringDimension = GetRingDimension();
  usint nTowers = m_vectors.size();

  DEBUG("in Interpolate ring " << ringDimension << " towers " << nTowers);

  for (usint vi = 0; vi < nTowers; vi++)
    DEBUG("tower " << vi << " is " << m_vectors[vi]);

  Integer bigModulus(GetModulus());  // qT

  DEBUG("bigModulus " << bigModulus);

  // this is the resulting vector of coefficients
  VecType coefficients(ringDimension, bigModulus);

  // this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj
  // *[ (qt/qj)^(-1) mod qj ]}modqt

  // first, precompute qt/qj factors
  vector<Integer> multiplier(nTowers);
  for (usint vi = 0; vi < nTowers; vi++) {
    Integer qj(m_vectors[vi].GetModulus().ConvertToInt());
    Integer divBy = bigModulus / qj;
    Integer modInv = divBy.ModInverse(qj).Mod(qj);
    multiplier[vi] = divBy * modInv;

    DEBUG("multiplier " << vi << " " << qj << " " << multiplier[vi]);
  }

  // if the vectors are not in COEFFICIENT form, they need to be, so we will
  // need to make a copy of them and switchformat on them... otherwise we can
  // just use what we have
  const std::vector<PolyType> *vecs = &m_vectors;
  std::vector<PolyType> coeffVecs;
  if (m_format == Format::EVALUATION) {
    for (usint ii = 0; ii < m_vectors.size(); ii++) {
      PolyType vecCopy(m_vectors[ii]);
      vecCopy.SetFormat(Format::COEFFICIENT);
      coeffVecs.push_back(std::move(vecCopy));
    }
    vecs = &coeffVecs;
  }

  for (usint vi = 0; vi < nTowers; vi++)
    DEBUG("tower " << vi << " is " << (*vecs)[vi]);

  // Precompute the Barrett mu parameter
  Integer mu = bigModulus.ComputeMu();

  // now, compute the value for the vector at element i

  for (usint ri = 0; ri < ringDimension; ri++) {
    coefficients[ri] = 0;
    if (ri == i) {
      for (usint vi = 0; vi < nTowers; vi++) {
        coefficients[ri] +=
            (Integer((*vecs)[vi].GetValues()[ri].ConvertToInt()) *
             multiplier[vi]);
      }
      DEBUG((*vecs)[0].GetValues()[ri] << " * " << multiplier[0]
                                       << " == " << coefficients[ri]);
      coefficients[ri].ModEq(bigModulus, mu);
    }
  }

  DEBUG("passed loops");
  DEBUG(coefficients);

  // Create an Poly for this BigVector

  DEBUG("elementing after vectoring");
  DEBUG("m_cyclotomicOrder " << GetCyclotomicOrder());
  DEBUG("modulus " << bigModulus);

  // Setting the root of unity to ONE as the calculation is expensive and not
  // required.
  typename DCRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed(
      std::make_shared<ILParamsImpl<Integer>>(GetCyclotomicOrder(), bigModulus,
                                              1));
  polynomialReconstructed.SetValues(std::move(coefficients), COEFFICIENT);

  DEBUG("answer: " << polynomialReconstructed);

  return polynomialReconstructed;
}

// todo can we be smarter with this method?
template <typename VecType>
NativePoly DCRTPolyImpl<VecType>::DecryptionCRTInterpolate(
    PlaintextModulus ptm) const {
  return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

// todo can we be smarter with this method?
template <typename VecType>
NativePoly DCRTPolyImpl<VecType>::ToNativePoly() const {
  return this->CRTInterpolate().ToNativePoly();
}

template <typename VecType>
BigInteger DCRTPolyImpl<VecType>::GetWorkingModulus() const {
  usint nTowersQ = m_vectors.size();
  BigInteger modulusQ = 1;
  for (size_t i = 0; i < nTowersQ; i++) {
    modulusQ *= m_params->GetParams()[i]->GetModulus();
  }
  return modulusQ;
}

template <typename VecType>
shared_ptr<typename DCRTPolyImpl<VecType>::Params>
DCRTPolyImpl<VecType>::GetExtendedCRTBasis(
    shared_ptr<DCRTPolyImpl::Params> paramsP) const {
  usint sizeQ = m_vectors.size();
  usint sizeP = paramsP->GetParams().size();
  usint sizeQP = sizeQ + sizeP;

  vector<NativeInteger> moduliQP(sizeQP);
  vector<NativeInteger> rootsQP(sizeQP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduliQP[i] = m_params->GetParams()[i]->GetModulus();
    rootsQP[i] = m_params->GetParams()[i]->GetRootOfUnity();
  }
  for (size_t i = sizeQ, j = 0; i < sizeQP; i++, j++) {
    moduliQP[i] = paramsP->GetParams()[j]->GetModulus();
    rootsQP[i] = paramsP->GetParams()[j]->GetRootOfUnity();
  }
  return std::make_shared<DCRTPolyImpl::Params>(2 * GetRingDimension(),
                                                moduliQP, rootsQP);
}

#if defined(HAVE_INT128) && NATIVEINT == 64 && !defined(__EMSCRIPTEN__)
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxSwitchCRTBasis(
    const shared_ptr<DCRTPolyImpl::Params> paramsQ,
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const vector<NativeInteger> &QHatInvModq,
    const vector<NativeInteger> &QHatInvModqPrecon,
    const vector<vector<NativeInteger>> &QHatModp,
    const vector<DoubleNativeInt> &modpBarrettMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  usint sizeQ = (m_vectors.size() > paramsQ->GetParams().size())
                    ? paramsQ->GetParams().size()
                    : m_vectors.size();
  usint sizeP = ans.m_vectors.size();

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    vector<DoubleNativeInt> sum(sizeP);
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &xi = m_vectors[i][ri];
      const NativeInteger &qi = m_vectors[i].GetModulus();
      NativeInteger xQHatInvModqi =
          xi.ModMulFastConst(QHatInvModq[i], qi, QHatInvModqPrecon[i]);
      for (usint j = 0; j < sizeP; j++) {
        sum[j] +=
            Mul128(xQHatInvModqi.ConvertToInt(), QHatModp[i][j].ConvertToInt());
      }
    }

    for (usint j = 0; j < sizeP; j++) {
      const NativeInteger &pj = ans.m_vectors[j].GetModulus();
      ans.m_vectors[j][ri] =
          BarrettUint128ModUint64(sum[j], pj.ConvertToInt(), modpBarrettMu[j]);
    }
  }

  return ans;
}
#else
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxSwitchCRTBasis(
    const shared_ptr<DCRTPolyImpl::Params> paramsQ,
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const vector<NativeInteger> &QHatInvModq,
    const vector<NativeInteger> &QHatInvModqPrecon,
    const vector<vector<NativeInteger>> &QHatModp,
    const vector<DoubleNativeInt> &modpBarrettMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint sizeQ = (m_vectors.size() > paramsQ->GetParams().size())
                    ? paramsQ->GetParams().size()
                    : m_vectors.size();
  usint sizeP = ans.m_vectors.size();

  for (usint i = 0; i < sizeQ; i++) {
    auto xQHatInvModqi = m_vectors[i] * QHatInvModq[i];
#pragma omp parallel for
    for (usint j = 0; j < sizeP; j++) {
      auto temp = xQHatInvModqi;
      temp.SwitchModulus(ans.m_vectors[j].GetModulus(),
                         ans.m_vectors[j].GetRootOfUnity());
      ans.m_vectors[j] += (temp *= QHatModp[i][j]);
    }
  }

  return ans;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::ApproxModUp(
    const shared_ptr<Params> paramsQ, const shared_ptr<Params> paramsP,
    const shared_ptr<Params> paramsQP, const vector<NativeInteger> &QHatInvModq,
    const vector<NativeInteger> &QHatInvModqPrecon,
    const vector<vector<NativeInteger>> &QHatModp,
    const vector<DoubleNativeInt> &modpBarrettMu) {
  std::vector<PolyType> polyInNTT;
  // if the input polynomial is in evaluation representation, store it for
  // later use to reduce the number of NTTs
  if (m_format == Format::EVALUATION) {
    polyInNTT = m_vectors;
    this->SetFormat(Format::COEFFICIENT);
  }

  usint sizeQ = m_vectors.size();
  usint sizeP = paramsP->GetParams().size();
  usint sizeQP = paramsQP->GetParams().size();

  DCRTPolyType partP =
      ApproxSwitchCRTBasis(paramsQ, paramsP, QHatInvModq, QHatInvModqPrecon,
                           QHatModp, modpBarrettMu);

  m_vectors.resize(sizeQP);

#pragma omp parallel for
  // populate the towers corresponding to CRT basis P and convert them to
  // evaluation representation
  for (size_t j = 0; j < sizeP; j++) {
    m_vectors[sizeQ + j] = partP.m_vectors[j];
    m_vectors[sizeQ + j].SetFormat(Format::EVALUATION);
  }
  // if the input polynomial was in evaluation representation, use the towers
  // for Q from it
  if (polyInNTT.size() > 0) {
    for (size_t i = 0; i < sizeQ; i++) {
      m_vectors[i] = polyInNTT[i];
    }
  } else {
// else call NTT for the towers for Q
#pragma omp parallel for
    for (size_t i = 0; i < sizeQ; i++) {
      m_vectors[i].SwitchFormat();
    }
  }

  m_format = Format::EVALUATION;
  m_params = paramsQP;
}

template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxModDown(
    const shared_ptr<Params> paramsQ, const shared_ptr<Params> paramsP,
    const vector<NativeInteger> &PInvModq,
    const vector<NativeInteger> &PInvModqPrecon,
    const vector<NativeInteger> &PHatInvModp,
    const vector<NativeInteger> &PHatInvModpPrecon,
    const vector<vector<NativeInteger>> &PHatModq,
    const vector<DoubleNativeInt> &modqBarrettMu,
    const vector<NativeInteger> &tInvModp,
    const vector<NativeInteger> &tInvModpPrecon, const NativeInteger &t,
    const vector<NativeInteger> &tModqPrecon) const {
  usint sizeQP = m_vectors.size();
  usint sizeP = paramsP->GetParams().size();
  usint sizeQ = sizeQP - sizeP;

  DCRTPolyType partP(paramsP, m_format, true);

  for (usint i = sizeQ, j = 0; i < sizeQP; i++, j++) {
    partP.m_vectors[j] = m_vectors[i];
  }

  partP.SetFormat(COEFFICIENT);

  // Multiply everything by -t^(-1) mod P (BGVrns only)
  if (t > 0) {
#pragma omp parallel for
    for (usint j = 0; j < sizeP; j++) {
      partP.m_vectors[j] *= tInvModp[j];
    }
  }

  DCRTPolyType partPSwitchedToQ =
      partP.ApproxSwitchCRTBasis(paramsP, paramsQ, PHatInvModp,
                                 PHatInvModpPrecon, PHatModq, modqBarrettMu);

  // Combine the switched DCRTPoly with the Q part of this to get the result
  DCRTPolyType ans(paramsQ, EVALUATION, true);
  uint32_t diffQ = paramsQ->GetParams().size() - sizeQ;
  if (diffQ > 0) ans.DropLastElements(diffQ);

  // Multiply everything by t mod Q (BGVrns only)
  if (t > 0) {
#pragma omp parallel for
    for (usint i = 0; i < sizeQ; i++) {
      partPSwitchedToQ.m_vectors[i] *= t;
    }
  }

  partPSwitchedToQ.SetFormat(EVALUATION);

#pragma omp parallel for
  for (usint i = 0; i < sizeQ; i++) {
    auto diff = m_vectors[i] - partPSwitchedToQ.m_vectors[i];
    ans.m_vectors[i] = diff * PInvModq[i];
  }

  return ans;
}

#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::SwitchCRTBasis(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<NativeInteger> &QHatInvModq,
    const std::vector<NativeInteger> &QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModp,
    const std::vector<std::vector<NativeInteger>> &alphaQModp,
    const std::vector<DoubleNativeInt> &modpBarrettMu,
    const std::vector<double> &qInv) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  usint sizeQ = m_vectors.size();
  usint sizeP = ans.m_vectors.size();

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    std::vector<NativeInteger> xQHatInvModq(sizeQ);
    double nu = 0.5;

    // Compute alpha and vector of x_i terms
    for (usint i = 0; i < sizeQ; i++) {
      //      const NativeInteger &xi = m_vectors[i][ri];
      const NativeInteger &qi = m_vectors[i].GetModulus();

      // computes [x_i (Q/q_i)^{-1}]_{q_i}
      xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi,
                                                         QHatInvModqPrecon[i]);

      // computes [x_i (Q/q_i)^{-1}]_{q_i} / q_i
      // to keep track of the number of q-overflows
      nu += static_cast<double>(xQHatInvModq[i].ConvertToInt()) * qInv[i];
    }

    // alpha corresponds to the number of overflows, 0 <= alpha <= sizeQ
    usint alpha = static_cast<usint>(nu);

    const std::vector<NativeInteger> &alphaQModpri = alphaQModp[alpha];

    for (usint j = 0; j < sizeP; j++) {
      DoubleNativeInt curValue = 0;

      const NativeInteger &pj = ans.m_vectors[j].GetModulus();
      const std::vector<NativeInteger> &QHatModpj = QHatModp[j];
      // first round - compute "fast conversion"
      for (usint i = 0; i < sizeQ; i++) {
        curValue +=
            Mul128(xQHatInvModq[i].ConvertToInt(), QHatModpj[i].ConvertToInt());
      }

      const NativeInteger &curNativeValue =
          NativeInteger(BarrettUint128ModUint64(curValue, pj.ConvertToInt(),
                                                modpBarrettMu[j]));

      // second round - remove q-overflows
      ans.m_vectors[j][ri] = curNativeValue.ModSubFast(alphaQModpri[j], pj);
    }
  }

  return ans;
}
#else
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::SwitchCRTBasis(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<NativeInteger> &QHatInvModq,
    const std::vector<NativeInteger> &QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModp,
    const std::vector<std::vector<NativeInteger>> &alphaQModp,
    const std::vector<DoubleNativeInt> &modpBarrettMu,
    const std::vector<double> &qInv) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  usint sizeQ = m_vectors.size();
  usint sizeP = ans.m_vectors.size();

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    std::vector<NativeInteger> xQHatInvModq(sizeQ);
    double nu = 0.5;

    // Compute alpha and vector of x_i terms
    for (usint i = 0; i < sizeQ; i++) {
      //      const NativeInteger &xi = m_vectors[i][ri];
      const NativeInteger &qi = m_vectors[i].GetModulus();

      // computes [x_i (Q/q_i)^{-1}]_{q_i}
      xQHatInvModq[i] = m_vectors[i][ri].ModMulFastConst(QHatInvModq[i], qi,
                                                         QHatInvModqPrecon[i]);

      // computes [x_i (Q/q_i)^{-1}]_{q_i} / q_i
      // to keep track of the number of q-overflows
      nu += static_cast<double>(xQHatInvModq[i].ConvertToInt()) * qInv[i];
    }

    // alpha corresponds to the number of overflows, 0 <= alpha <= sizeQ
    usint alpha = static_cast<usint>(nu);

    const std::vector<NativeInteger> &alphaQModpri = alphaQModp[alpha];

    vector<NativeInteger> mu(sizeP);
    for (usint j = 0; j < sizeP; j++) {
      mu[j] = ans.m_vectors[j].GetModulus().ComputeMu();
    }

    for (usint j = 0; j < sizeP; j++) {
      const NativeInteger &pj = ans.m_vectors[j].GetModulus();
      const std::vector<NativeInteger> &QHatModpj = QHatModp[j];
      // first round - compute "fast conversion"
      for (usint i = 0; i < sizeQ; i++) {
        ans.m_vectors[j][ri].ModAddFastEq(
            xQHatInvModq[i].ModMulFast(QHatModpj[i], pj, mu[j]), pj);
      }

      // second round - remove q-overflows
      ans.m_vectors[j][ri].ModSubFastEq(alphaQModpri[j], pj);
    }
  }

  return ans;
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::ExpandCRTBasis(
    const shared_ptr<DCRTPolyImpl::Params> paramsQP,
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<NativeInteger> &QHatInvModq,
    const std::vector<NativeInteger> &QHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModp,
    const std::vector<std::vector<NativeInteger>> &alphaQModp,
    const std::vector<DoubleNativeInt> &modpBarrettMu,
    const std::vector<double> &qInv, Format resultFormat) {
  std::vector<PolyType> polyInNTT;

  // if the input polynomial is in evaluation representation, store it for
  // later use to reduce the number of NTTs
  if (this->GetFormat() == Format::EVALUATION) {
    polyInNTT = m_vectors;
    this->SetFormat(Format::COEFFICIENT);
  }

  DCRTPolyType partP =
      SwitchCRTBasis(paramsP, QHatInvModq, QHatInvModqPrecon, QHatModp,
                     alphaQModp, modpBarrettMu, qInv);

  size_t sizeQ = m_vectors.size();
  size_t sizeP = partP.m_vectors.size();
  size_t sizeQP = sizeP + sizeQ;

  m_vectors.resize(sizeQP);

#pragma omp parallel for
  // populate the towers corresponding to CRT basis P and convert them to
  // evaluation representation
  for (size_t j = 0; j < sizeP; j++) {
    m_vectors[sizeQ + j] = partP.m_vectors[j];
    m_vectors[sizeQ + j].SetFormat(resultFormat);
  }

  if (resultFormat == Format::EVALUATION) {
    // if the input polynomial was in evaluation representation, use the towers
    // for Q from it
    if (polyInNTT.size() > 0) {
      for (size_t i = 0; i < sizeQ; i++) m_vectors[i] = polyInNTT[i];
    } else {
      // else call NTT for the towers for Q
#pragma omp parallel for
      for (size_t i = 0; i < sizeQ; i++) m_vectors[i].SetFormat(resultFormat);
    }
  }
  m_format = resultFormat;
  m_params = paramsQP;
}

template <typename VecType>
PolyImpl<NativeVector> DCRTPolyImpl<VecType>::ScaleAndRound(
    const NativeInteger &t,
    const std::vector<NativeInteger> &tQHatInvModqDivqModt,
    const std::vector<NativeInteger> &tQHatInvModqDivqModtPrecon,
    const std::vector<NativeInteger> &tQHatInvModqBDivqModt,
    const std::vector<NativeInteger> &tQHatInvModqBDivqModtPrecon,
    const std::vector<double> &tQHatInvModqDivqFrac,
    const std::vector<double> &tQHatInvModqDivqBFrac) const {
  usint ringDim = GetRingDimension();
  usint sizeQ = m_vectors.size();

  // MSB of q_i
  usint qMSB = m_vectors[0].GetModulus().GetMSB();
  // MSB of t
  usint tMSB = t.GetMSB();
  // MSB of sizeQ
  usint sizeQMSB = GetMSB64(sizeQ);

  typename PolyType::Vector coefficients(ringDim, t.ConvertToInt());
  // For power of two t we can do modulo reduction easily
  if (IsPowerOfTwo(t.ConvertToInt())) {
    uint64_t tMinus1 = t.ConvertToInt() - 1;
    // We try to keep floating point error of
    // \sum x_i*tQHatInvModqDivqFrac[i] small.
    if (qMSB + sizeQMSB < 52) {
      // In our settings x_i <= q_i/2 and for double type floating point
      // error is bounded by 2^{-53}. Thus the floating point error is bounded
      // by sizeQ * q_i/2 * 2^{-53}. In case of qMSB + sizeQMSB < 52 the error
      // is bounded by 1/4, and the rounding will be correct.
      if ((qMSB + tMSB + sizeQMSB) < 63) {
        // No intermediate modulo reductions are needed in this case
        // we fit in 63 bits, so we can do multiplications and
        // additions without modulo reduction, and do modulo reduction
        // only once
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.5;
          NativeInteger intSum = 0, tmp;
          for (usint i = 0; i < sizeQ; i++) {
            tmp = m_vectors[i][ri];

            floatSum += static_cast<double>(tmp.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];

            // No intermediate modulo reductions are needed in this case
            tmp.MulEqFast(tQHatInvModqDivqModt[i]);
            intSum.AddEqFast(tmp);
          }
          intSum += static_cast<uint64_t>(floatSum);
          // mod a power of two
          coefficients[ri] = intSum.ConvertToInt() & tMinus1;
        }
      } else {
        // In case of qMSB + sizeQMSB >= 52 we decompose x_i in the basis
        // B=2^{qMSB/2} And split the sum \sum x_i*tQHatInvModqDivqFrac[i] to
        // the sum \sum xLo_i*tQHatInvModqDivqFrac[i] +
        // xHi_i*tQHatInvModqBDivqFrac[i] with also precomputed
        // tQHatInvModqBDivqFrac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
        // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
        // is bounded by 2^{-53}. Thus the floating point error is bounded by
        // sizeQ * 2^30 * 2^{-53}. We always have sizeQ < 2^11, which means the
        // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.5;
          NativeInteger intSum = 0, tmp;
          for (usint i = 0; i < sizeQ; i++) {
            tmp = m_vectors[i][ri];

            floatSum += static_cast<double>(tmp.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];

            tmp.ModMulFastConstEq(tQHatInvModqDivqModt[i], t,
                                  tQHatInvModqDivqModtPrecon[i]);
            intSum.AddEqFast(tmp);
          }
          intSum += static_cast<uint64_t>(floatSum);
          // mod a power of two
          coefficients[ri] = intSum.ConvertToInt() & tMinus1;
        }
      }
    } else {
      usint qMSBHf = qMSB >> 1;
      if ((qMSBHf + tMSB + sizeQMSB) < 62) {
        // No intermediate modulo reductions are needed in this case
        // we fit in 62 bits, so we can do multiplications and
        // additions without modulo reduction, and do modulo reduction
        // only once
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.5;
          NativeInteger intSum = 0;
          NativeInteger tmpHi, tmpLo;
          for (usint i = 0; i < sizeQ; i++) {
            tmpLo = m_vectors[i][ri];
            tmpHi = tmpLo.RShift(qMSBHf);
            tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

            floatSum += static_cast<double>(tmpLo.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];
            floatSum += static_cast<double>(tmpHi.ConvertToInt()) *
                        tQHatInvModqDivqBFrac[i];

            // No intermediate modulo reductions are needed in this case
            tmpLo.MulEqFast(tQHatInvModqDivqModt[i]);
            tmpHi.MulEqFast(tQHatInvModqBDivqModt[i]);
            intSum.AddEqFast(tmpLo);
            intSum.AddEqFast(tmpHi);
          }
          intSum += static_cast<uint64_t>(floatSum);
          // mod a power of two
          coefficients[ri] = intSum.ConvertToInt() & tMinus1;
        }
      } else {
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.5;
          NativeInteger intSum = 0;
          NativeInteger tmpHi, tmpLo;
          for (usint i = 0; i < sizeQ; i++) {
            tmpLo = m_vectors[i][ri];
            tmpHi = tmpLo.RShift(qMSBHf);
            tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

            floatSum += static_cast<double>(tmpLo.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];
            floatSum += static_cast<double>(tmpHi.ConvertToInt()) *
                        tQHatInvModqDivqBFrac[i];

            tmpLo.ModMulFastConstEq(tQHatInvModqDivqModt[i], t,
                                    tQHatInvModqDivqModtPrecon[i]);
            tmpHi.ModMulFastConstEq(tQHatInvModqBDivqModt[i], t,
                                    tQHatInvModqBDivqModtPrecon[i]);
            intSum.AddEqFast(tmpLo);
            intSum.AddEqFast(tmpHi);
          }
          intSum += static_cast<uint64_t>(floatSum);
          // mod a power of two
          coefficients[ri] = intSum.ConvertToInt() & tMinus1;
        }
      }
    }
  } else {
    // non-power of two: modular reduction is more expensive
    double td = t.ConvertToInt();
    double tInv = 1. / td;
    // We try to keep floating point error of
    // \sum x_i*tQHatInvModqDivqFrac[i] small.
    if (qMSB + sizeQMSB < 52) {
      // In our settings x_i <= q_i/2 and for double type floating point
      // error is bounded by 2^{-53}. Thus the floating point error is bounded
      // by sizeQ * q_i/2 * 2^{-53}. In case of qMSB + sizeQMSB < 52 the error
      // is bounded by 1/4, and the rounding will be correct.
      if ((qMSB + tMSB + sizeQMSB) < 52) {
        // No intermediate modulo reductions are needed in this case
        // we fit in 52 bits, so we can do multiplications and
        // additions without modulo reduction, and do modulo reduction
        // only once using floating point techniques
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.0;
          NativeInteger intSum = 0, tmp;
          for (usint i = 0; i < sizeQ; i++) {
            tmp = m_vectors[i][ri];

            floatSum += static_cast<double>(tmp.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];

            // No intermediate modulo reductions are needed in this case
            tmp.MulEqFast(tQHatInvModqDivqModt[i]);
            intSum.AddEqFast(tmp);
          }
          // compute modulo reduction by finding the quotient using doubles
          // and then substracting quotient * t
          floatSum += intSum.ConvertToInt();
          uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
          floatSum -= td * quot;
          // rounding
          coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
        }
      } else {
        // In case of qMSB + sizeQMSB >= 52 we decompose x_i in the basis
        // B=2^{qMSB/2} And split the sum \sum x_i*tQHatInvModqDivqFrac[i] to
        // the sum \sum xLo_i*tQHatInvModqDivqFrac[i] +
        // xHi_i*tQHatInvModqBDivqFrac[i] with also precomputed
        // tQHatInvModqBDivqFrac = Frac{t*QHatInv_i*B/q_i} In our settings q_i <
        // 2^60, so xLo_i, xHi_i < 2^30 and for double type floating point error
        // is bounded by 2^{-53}. Thus the floating point error is bounded by
        // sizeQ * 2^30 * 2^{-53}. We always have sizeQ < 2^11, which means the
        // error is bounded by 1/4, and the rounding will be correct.
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.0;
          NativeInteger intSum = 0, tmp;
          for (usint i = 0; i < sizeQ; i++) {
            tmp = m_vectors[i][ri];

            floatSum += static_cast<double>(tmp.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];

            tmp.ModMulFastConstEq(tQHatInvModqDivqModt[i], t,
                                  tQHatInvModqDivqModtPrecon[i]);
            intSum.AddEqFast(tmp);
          }
          // compute modulo reduction by finding the quotient using doubles
          // and then substracting quotient * t
          floatSum += intSum.ConvertToInt();
          uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
          floatSum -= td * quot;
          // rounding
          coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
        }
      }
    } else {
      usint qMSBHf = qMSB >> 1;
      if ((qMSBHf + tMSB + sizeQMSB) < 52) {
        // No intermediate modulo reductions are needed in this case
        // we fit in 52 bits, so we can do multiplications and
        // additions without modulo reduction, and do modulo reduction
        // only once using floating point techniques
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.0;
          NativeInteger intSum = 0;
          NativeInteger tmpHi, tmpLo;
          for (usint i = 0; i < sizeQ; i++) {
            tmpLo = m_vectors[i][ri];
            tmpHi = tmpLo.RShift(qMSBHf);
            tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

            floatSum += static_cast<double>(tmpLo.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];
            floatSum += static_cast<double>(tmpHi.ConvertToInt()) *
                        tQHatInvModqDivqBFrac[i];

            // No intermediate modulo reductions are needed in this case
            tmpLo.MulEqFast(tQHatInvModqDivqModt[i]);
            tmpHi.MulEqFast(tQHatInvModqBDivqModt[i]);
            intSum.AddEqFast(tmpLo);
            intSum.AddEqFast(tmpHi);
          }
          // compute modulo reduction by finding the quotient using doubles
          // and then substracting quotient * t
          floatSum += intSum.ConvertToInt();
          uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
          floatSum -= td * quot;
          // rounding
          coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
        }
      } else {
#pragma omp parallel for
        for (usint ri = 0; ri < ringDim; ri++) {
          double floatSum = 0.0;
          NativeInteger intSum = 0;
          NativeInteger tmpHi, tmpLo;
          for (usint i = 0; i < sizeQ; i++) {
            tmpLo = m_vectors[i][ri];
            tmpHi = tmpLo.RShift(qMSBHf);
            tmpLo.SubEqFast(tmpHi.LShift(qMSBHf));

            floatSum += static_cast<double>(tmpLo.ConvertToInt()) *
                        tQHatInvModqDivqFrac[i];
            floatSum += static_cast<double>(tmpHi.ConvertToInt()) *
                        tQHatInvModqDivqBFrac[i];

            tmpLo.ModMulFastConstEq(tQHatInvModqDivqModt[i], t,
                                    tQHatInvModqDivqModtPrecon[i]);
            tmpHi.ModMulFastConstEq(tQHatInvModqBDivqModt[i], t,
                                    tQHatInvModqBDivqModtPrecon[i]);
            intSum.AddEqFast(tmpLo);
            intSum.AddEqFast(tmpHi);
          }
          // compute modulo reduction by finding the quotient using doubles
          // and then substracting quotient * t
          floatSum += intSum.ConvertToInt();
          uint64_t quot = static_cast<uint64_t>(floatSum * tInv);
          floatSum -= td * quot;
          // rounding
          coefficients[ri] = static_cast<uint64_t>(floatSum + 0.5);
        }
      }
    }
  }

  // Setting the root of unity to ONE as the calculation is expensive
  // It is assumed that no polynomial multiplications in evaluation
  // representation are performed after this
  PolyType result(std::make_shared<typename PolyType::Params>(
      GetCyclotomicOrder(), t.ConvertToInt(), 1));
  result.SetValues(std::move(coefficients), Format::COEFFICIENT);

  return result;
}

#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxScaleAndRound(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<std::vector<NativeInteger>> &tPSHatInvModsDivsModp,
    const std::vector<DoubleNativeInt> &modpBarretMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  size_t sizeQP = m_vectors.size();
  size_t sizeP = ans.m_vectors.size();
  size_t sizeQ = sizeQP - sizeP;

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    for (usint j = 0; j < sizeP; j++) {
      DoubleNativeInt curValue = 0;

      const NativeInteger &pj = paramsP->GetParams()[j]->GetModulus();
      const std::vector<NativeInteger> &tPSHatInvModsDivsModpj =
          tPSHatInvModsDivsModp[j];

      for (usint i = 0; i < sizeQ; i++) {
        const NativeInteger &xi = m_vectors[i][ri];
        curValue +=
            Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[i].ConvertToInt());
      }

      const NativeInteger &xi = m_vectors[sizeQ + j][ri];
      curValue += Mul128(xi.ConvertToInt(),
                         tPSHatInvModsDivsModpj[sizeQ].ConvertToInt());

      ans.m_vectors[j][ri] =
          BarrettUint128ModUint64(curValue, pj.ConvertToInt(), modpBarretMu[j]);
    }
  }

  return ans;
}
#else
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ApproxScaleAndRound(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<std::vector<NativeInteger>> &tPSHatInvModsDivsModp,
    const std::vector<DoubleNativeInt> &modpBarretMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  size_t sizeQP = m_vectors.size();
  size_t sizeP = ans.m_vectors.size();
  size_t sizeQ = sizeQP - sizeP;

  vector<NativeInteger> mu(sizeP);
  for (usint j = 0; j < sizeP; j++) {
    mu[j] = (paramsP->GetParams()[j]->GetModulus()).ComputeMu();
  }

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    for (usint j = 0; j < sizeP; j++) {
      const NativeInteger &pj = paramsP->GetParams()[j]->GetModulus();
      const std::vector<NativeInteger> &tPSHatInvModsDivsModpj =
          tPSHatInvModsDivsModp[j];

      for (usint i = 0; i < sizeQ; i++) {
        const NativeInteger &xi = m_vectors[i][ri];
        const NativeInteger &pj = ans.m_vectors[j].GetModulus();
        ans.m_vectors[j][ri].ModAddFastEq(
            xi.ModMulFast(tPSHatInvModsDivsModpj[i], pj, mu[j]), pj);
      }

      const NativeInteger &xi = m_vectors[sizeQ + j][ri];
      ans.m_vectors[j][ri].ModAddFastEq(
          xi.ModMulFast(tPSHatInvModsDivsModpj[sizeQ], pj, mu[j]), pj);
    }
  }

  return ans;
}
#endif

#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ScaleAndRound(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<std::vector<NativeInteger>> &tPSHatInvModsDivsModp,
    const std::vector<double> &tPSHatInvModsDivsFrac,
    const std::vector<DoubleNativeInt> &modpBarretMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  size_t sizeQP = m_vectors.size();
  size_t sizeP = ans.m_vectors.size();
  size_t sizeQ = sizeQP - sizeP;

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    double nu = 0.5;

    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &xi = m_vectors[i][ri];
      nu += tPSHatInvModsDivsFrac[i] * xi.ConvertToInt();
    }

    NativeInteger alpha = static_cast<uint64_t>(nu);

    for (usint j = 0; j < sizeP; j++) {
      DoubleNativeInt curValue = 0;

      const NativeInteger &pj = paramsP->GetParams()[j]->GetModulus();
      const std::vector<NativeInteger> &tPSHatInvModsDivsModpj =
          tPSHatInvModsDivsModp[j];

      for (usint i = 0; i < sizeQ; i++) {
        const NativeInteger &xi = m_vectors[i][ri];
        curValue +=
            Mul128(xi.ConvertToInt(), tPSHatInvModsDivsModpj[i].ConvertToInt());
      }

      const NativeInteger &xi = m_vectors[sizeQ + j][ri];
      curValue += Mul128(xi.ConvertToInt(),
                         tPSHatInvModsDivsModpj[sizeQ].ConvertToInt());

      const NativeInteger &curNativeValue =
          NativeInteger(BarrettUint128ModUint64(curValue, pj.ConvertToInt(),
                                                modpBarretMu[j]));

      ans.m_vectors[j][ri] = curNativeValue.ModAddFast(alpha, pj);
    }
  }

  return ans;
}
#else
template <typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::ScaleAndRound(
    const shared_ptr<DCRTPolyImpl::Params> paramsP,
    const std::vector<std::vector<NativeInteger>> &tPSHatInvModsDivsModp,
    const std::vector<double> &tPSHatInvModsDivsFrac,
    const std::vector<DoubleNativeInt> &modpBarretMu) const {
  DCRTPolyType ans(paramsP, m_format, true);

  usint ringDim = GetRingDimension();
  size_t sizeQP = m_vectors.size();
  size_t sizeP = ans.m_vectors.size();
  size_t sizeQ = sizeQP - sizeP;

  vector<NativeInteger> mu(sizeP);
  for (usint j = 0; j < sizeP; j++) {
    mu[j] = (paramsP->GetParams()[j]->GetModulus()).ComputeMu();
  }

#pragma omp parallel for
  for (usint ri = 0; ri < ringDim; ri++) {
    double nu = 0.5;

    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &xi = m_vectors[i][ri];
      nu += tPSHatInvModsDivsFrac[i] * xi.ConvertToInt();
    }

    NativeInteger alpha = static_cast<uint64_t>(nu);

    for (usint j = 0; j < sizeP; j++) {
      const NativeInteger &pj = paramsP->GetParams()[j]->GetModulus();
      const std::vector<NativeInteger> &tPSHatInvModsDivsModpj =
          tPSHatInvModsDivsModp[j];

      for (usint i = 0; i < sizeQ; i++) {
        const NativeInteger &xi = m_vectors[i][ri];
        const NativeInteger &pj = ans.m_vectors[j].GetModulus();
        ans.m_vectors[j][ri].ModAddFastEq(
            xi.ModMulFast(tPSHatInvModsDivsModpj[i], pj, mu[j]), pj);
      }

      const NativeInteger &xi = m_vectors[sizeQ + j][ri];
      ans.m_vectors[j][ri].ModAddFastEq(
          xi.ModMulFast(tPSHatInvModsDivsModpj[sizeQ], pj, mu[j]), pj);
      ans.m_vectors[j][ri].ModAddFastEq(alpha, pj);
    }
  }

  return ans;
}
#endif

template <typename VecType>
PolyImpl<NativeVector> DCRTPolyImpl<VecType>::ScaleAndRound(
    const std::vector<NativeInteger> &moduliQ, const NativeInteger &t,
    const NativeInteger &tgamma,
    const std::vector<NativeInteger> &tgammaQHatModq,
    const std::vector<NativeInteger> &tgammaQHatModqPrecon,
    const std::vector<NativeInteger> &negInvqModtgamma,
    const std::vector<NativeInteger> &negInvqModtgammaPrecon) const {
  usint n = GetRingDimension();
  usint sizeQ = m_vectors.size();

  const uint64_t gammaMinus1 = (1 << 26) - 1;

  typename PolyType::Vector coefficients(n, t.ConvertToInt());

#pragma omp parallel for
  for (usint k = 0; k < n; k++) {
    // TODO: use 64 bit words in case NativeInteger uses smaller word size
    NativeInteger s = 0, tmp;
    for (usint i = 0; i < sizeQ; i++) {
      const NativeInteger &qi = moduliQ[i];
      tmp = m_vectors[i][k];

      // xi*t*gamma*(q/qi)^-1 mod qi
      tmp.ModMulFastConstEq(tgammaQHatModq[i], qi, tgammaQHatModqPrecon[i]);

      // -tmp/qi mod gamma*t < 2^58
      tmp = tmp.ModMulFastConst(negInvqModtgamma[i], tgamma,
                                negInvqModtgammaPrecon[i]);

      s.ModAddFastEq(tmp, tgamma);
    }

    // Compute s + s & (gamma-1)
    s += NativeInteger(s.ConvertToInt() & gammaMinus1);

    // shift by log(gamma) to get the result
    coefficients[k] = s >> 26;
  }

  // Setting the root of unity to ONE as the calculation is expensive
  // It is assumed that no polynomial multiplications in evaluation
  // representation are performed after this
  PolyType result(std::make_shared<typename PolyType::Params>(
      GetCyclotomicOrder(), t.ConvertToInt(), 1));
  result.SetValues(std::move(coefficients), Format::COEFFICIENT);

  return result;
}

#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvqToBskMontgomery(
    const shared_ptr<DCRTPolyImpl::Params> paramsBsk,
    const std::vector<NativeInteger> &moduliQ,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &mtildeQHatInvModq,
    const std::vector<NativeInteger> &mtildeQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModbsk,
    const std::vector<uint16_t> &QHatModmtilde,
    const std::vector<NativeInteger> &QModbsk,
    const std::vector<NativeInteger> &QModbskPrecon,
    const uint16_t &negQInvModmtilde,
    const std::vector<NativeInteger> &mtildeInvModbsk,
    const std::vector<NativeInteger> &mtildeInvModbskPrecon) {
  // Input: poly in basis q
  // Output: poly in base Bsk = {B U msk}

  // computing steps 0 and 1 in Algorithm 3 in source paper.

  std::vector<PolyType> polyInNTT;

  // if the input polynomial is in evaluation representation, store it for
  // later use to reduce the number of NTTs
  if (this->GetFormat() == Format::EVALUATION) {
    polyInNTT = m_vectors;
    this->SetFormat(Format::COEFFICIENT);
  }

  size_t numQ = moduliQ.size();
  size_t numBsk = moduliBsk.size();
  size_t numQBsk = numQ + moduliBsk.size();

  m_vectors.resize(numQBsk);

  uint32_t n = GetLength();

  m_params = paramsBsk;

  // ----------------------- step 0 -----------------------

  // first we twist xi by mtilde*(q/qi)^-1 mod qi
  NativeInteger *ximtildeQHatModqi = new NativeInteger[n * numQ];
  for (uint32_t i = 0; i < numQ; i++) {
    const NativeInteger &currentmtildeQHatInvModq = mtildeQHatInvModq[i];
    const NativeInteger &currentmtildeQHatInvModqPrecon =
        mtildeQHatInvModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      ximtildeQHatModqi[i * n + k] = m_vectors[i][k].ModMulFastConst(
          currentmtildeQHatInvModq, moduliQ[i], currentmtildeQHatInvModqPrecon);
    }
  }

  // mod Bsk
  for (uint32_t j = 0; j < numBsk; j++) {
    PolyType newvec(m_params->GetParams()[j], m_format, true);
    m_vectors[numQ + j] = std::move(newvec);
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      DoubleNativeInt result = 0;
      for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger &QHatModbskij = QHatModbsk[i][j];
        result += Mul128(ximtildeQHatModqi[i * n + k].ConvertToInt(),
                         QHatModbskij.ConvertToInt());
      }

      m_vectors[numQ + j][k] = BarrettUint128ModUint64(
          result, moduliBsk[j].ConvertToInt(), modbskBarrettMu[j]);
    }
  }

  // mod mtilde = 2^16
  std::vector<uint16_t> result_mtilde(n);
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    result_mtilde[k] = 0;
    for (uint32_t i = 0; i < numQ; i++)
      result_mtilde[k] +=
          ximtildeQHatModqi[i * n + k].ConvertToInt() * QHatModmtilde[i];
  }

  // now we have input in Basis (q U Bsk U mtilde)
  // next we perform Small Motgomery Reduction mod q
  // ----------------------- step 1 -----------------------
  // NativeInteger *r_m_tildes = new NativeInteger[n];

  uint64_t mtilde = (uint64_t)1 << 16;
  uint64_t mtilde_half = mtilde >> 1;

#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    result_mtilde[k] *= negQInvModmtilde;
  }

  for (uint32_t i = 0; i < numBsk; i++) {
    const NativeInteger &currentqModBski = QModbsk[i];
    const NativeInteger &currentqModBskiPrecon = QModbskPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      NativeInteger r_m_tilde =
          NativeInteger(result_mtilde[k]);  // mtilde = 2^16 < all moduli of Bsk
      if (result_mtilde[k] >= mtilde_half)
        r_m_tilde += moduliBsk[i] - mtilde;  // centred remainder

      r_m_tilde.ModMulFastConstEq(
          currentqModBski, moduliBsk[i],
          currentqModBskiPrecon);  // (r_mtilde) * q mod Bski
      r_m_tilde.ModAddFastEq(m_vectors[numQ + i][k],
                             moduliBsk[i]);  // (c``_m + (r_mtilde* q)) mod Bski
      m_vectors[numQ + i][k] = r_m_tilde.ModMulFastConst(
          mtildeInvModbsk[i], moduliBsk[i], mtildeInvModbskPrecon[i]);
    }
  }

  // if the input polynomial was in evaluation representation, use the towers
  // for Q from it
  if (polyInNTT.size() > 0) {
    for (size_t i = 0; i < numQ; i++) m_vectors[i] = polyInNTT[i];
  } else {  // else call NTT for the towers for q
#pragma omp parallel for
    for (size_t i = 0; i < numQ; i++) m_vectors[i].SwitchFormat();
  }

#pragma omp parallel for
  for (uint32_t i = 0; i < numBsk; i++) m_vectors[numQ + i].SwitchFormat();

  m_format = Format::EVALUATION;

  delete[] ximtildeQHatModqi;
  ximtildeQHatModqi = nullptr;
}
#else
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvqToBskMontgomery(
    const shared_ptr<DCRTPolyImpl::Params> paramsBsk,
    const std::vector<NativeInteger> &moduliQ,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &mtildeQHatInvModq,
    const std::vector<NativeInteger> &mtildeQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModbsk,
    const std::vector<uint16_t> &QHatModmtilde,
    const std::vector<NativeInteger> &QModbsk,
    const std::vector<NativeInteger> &QModbskPrecon,
    const uint16_t &negQInvModmtilde,
    const std::vector<NativeInteger> &mtildeInvModbsk,
    const std::vector<NativeInteger> &mtildeInvModbskPrecon) {
  // Input: poly in basis q
  // Output: poly in base Bsk = {B U msk}

  // computing steps 0 and 1 in Algorithm 3 in source paper.

  std::vector<PolyType> polyInNTT;

  // if the input polynomial is in evaluation representation, store it for
  // later use to reduce the number of NTTs
  if (this->GetFormat() == Format::EVALUATION) {
    polyInNTT = m_vectors;
    this->SetFormat(Format::COEFFICIENT);
  }

  size_t numQ = moduliQ.size();
  size_t numBsk = moduliBsk.size();
  size_t numQBsk = numQ + moduliBsk.size();

  m_vectors.resize(numQBsk);

  uint32_t n = GetLength();

  m_params = paramsBsk;

  // ----------------------- step 0 -----------------------

  // first we twist xi by mtilde*(q/qi)^-1 mod qi
  NativeInteger *ximtildeQHatModqi = new NativeInteger[n * numQ];
  for (uint32_t i = 0; i < numQ; i++) {
    const NativeInteger &currentmtildeQHatInvModq = mtildeQHatInvModq[i];
    const NativeInteger &currentmtildeQHatInvModqPrecon =
        mtildeQHatInvModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      ximtildeQHatModqi[i * n + k] = m_vectors[i][k].ModMulFastConst(
          currentmtildeQHatInvModq, moduliQ[i], currentmtildeQHatInvModqPrecon);
    }
  }

  vector<NativeInteger> mu(numBsk);
  for (usint j = 0; j < numBsk; j++) {
    mu[j] = moduliBsk[j].ComputeMu();
  }

  // mod Bsk
  for (uint32_t j = 0; j < numBsk; j++) {
    PolyType newvec(m_params->GetParams()[j], m_format, true);
    m_vectors[numQ + j] = std::move(newvec);
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger &QHatModbskij = QHatModbsk[i][j];
        m_vectors[numQ + j][k].ModAddFastEq(
            ximtildeQHatModqi[i * n + k].ModMulFast(QHatModbskij, moduliBsk[j],
                                                    mu[j]),
            moduliBsk[j]);
      }
    }
  }

  // mod mtilde = 2^16
  std::vector<uint16_t> result_mtilde(n);
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    result_mtilde[k] = 0;
    for (uint32_t i = 0; i < numQ; i++)
      result_mtilde[k] +=
          ximtildeQHatModqi[i * n + k].ConvertToInt() * QHatModmtilde[i];
  }

  // now we have input in Basis (q U Bsk U mtilde)
  // next we perform Small Motgomery Reduction mod q
  // ----------------------- step 1 -----------------------
  // NativeInteger *r_m_tildes = new NativeInteger[n];

  uint64_t mtilde = (uint64_t)1 << 16;
  uint64_t mtilde_half = mtilde >> 1;

#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    result_mtilde[k] *= negQInvModmtilde;
  }

  for (uint32_t i = 0; i < numBsk; i++) {
    const NativeInteger &currentqModBski = QModbsk[i];
    const NativeInteger &currentqModBskiPrecon = QModbskPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      NativeInteger r_m_tilde =
          NativeInteger(result_mtilde[k]);  // mtilde = 2^16 < all moduli of Bsk
      if (result_mtilde[k] >= mtilde_half)
        r_m_tilde += moduliBsk[i] - mtilde;  // centred remainder

      r_m_tilde.ModMulFastConstEq(
          currentqModBski, moduliBsk[i],
          currentqModBskiPrecon);  // (r_mtilde) * q mod Bski
      r_m_tilde.ModAddFastEq(m_vectors[numQ + i][k],
                             moduliBsk[i]);  // (c``_m + (r_mtilde* q)) mod Bski
      m_vectors[numQ + i][k] = r_m_tilde.ModMulFastConst(
          mtildeInvModbsk[i], moduliBsk[i], mtildeInvModbskPrecon[i]);
    }
  }

  // if the input polynomial was in evaluation representation, use the towers
  // for Q from it
  if (polyInNTT.size() > 0) {
    for (size_t i = 0; i < numQ; i++) m_vectors[i] = polyInNTT[i];
  } else {  // else call NTT for the towers for q
#pragma omp parallel for
    for (size_t i = 0; i < numQ; i++) m_vectors[i].SwitchFormat();
  }

#pragma omp parallel for
  for (uint32_t i = 0; i < numBsk; i++) m_vectors[numQ + i].SwitchFormat();

  m_format = EVALUATION;

  delete[] ximtildeQHatModqi;
  ximtildeQHatModqi = nullptr;
}
#endif
#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
void DCRTPolyImpl<VecType>::FastRNSFloorq(
    const NativeInteger &t, const std::vector<NativeInteger> &moduliQ,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &tQHatInvModq,
    const std::vector<NativeInteger> &tQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModbsk,
    const std::vector<std::vector<NativeInteger>> &qInvModbsk,
    const std::vector<NativeInteger> &tQInvModbsk,
    const std::vector<NativeInteger> &tQInvModbskPrecon) {
  // Input: poly in basis {q U Bsk}
  // Output: approximateFloor(t/q*poly) in basis Bsk

  // --------------------- step 3 ---------------------
  // approximate rounding

  size_t numQ = moduliQ.size();
  size_t numBsk = moduliBsk.size();

  uint32_t n = GetLength();

  // Twist xi by t*(q/qi)^-1 mod qi
  NativeInteger *txiqiDivqModqi = new NativeInteger[n * numBsk];

  for (uint32_t i = 0; i < numQ; i++) {
    const NativeInteger &currenttqDivqiModqi = tQHatInvModq[i];
    const NativeInteger &currenttqDivqiModqiPrecon = tQHatInvModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      // multiply by t*(q/qi)^-1 mod qi
      m_vectors[i][k].ModMulFastConstEq(currenttqDivqiModqi, moduliQ[i],
                                        currenttqDivqiModqiPrecon);
    }
  }

  for (uint32_t j = 0; j < numBsk; j++) {
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      DoubleNativeInt aq = 0;
      for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger &InvqiModBjValue = qInvModbsk[i][j];
        NativeInteger &xi = m_vectors[i][k];
        aq += Mul128(xi.ConvertToInt(), InvqiModBjValue.ConvertToInt());
      }
      txiqiDivqModqi[j * n + k] = BarrettUint128ModUint64(
          aq, moduliBsk[j].ConvertToInt(), modbskBarrettMu[j]);
    }
  }

  // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi

  for (uint32_t i = 0; i < numBsk; i++) {
    const NativeInteger &currenttDivqModBski = tQInvModbsk[i];
    const NativeInteger &currenttDivqModBskiPrecon = tQInvModbskPrecon[i];
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      // Not worthy to use lazy reduction here
      m_vectors[i + numQ][k].ModMulFastConstEq(
          currenttDivqModBski, moduliBsk[i], currenttDivqModBskiPrecon);
      m_vectors[i + numQ][k].ModSubFastEq(txiqiDivqModqi[i * n + k],
                                          moduliBsk[i]);
    }
  }
  delete[] txiqiDivqModqi;
  txiqiDivqModqi = nullptr;
}
#else
template <typename VecType>
void DCRTPolyImpl<VecType>::FastRNSFloorq(
    const NativeInteger &t, const std::vector<NativeInteger> &moduliQ,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &tQHatInvModq,
    const std::vector<NativeInteger> &tQHatInvModqPrecon,
    const std::vector<std::vector<NativeInteger>> &QHatModbsk,
    const std::vector<std::vector<NativeInteger>> &qInvModbsk,
    const std::vector<NativeInteger> &tQInvModbsk,
    const std::vector<NativeInteger> &tQInvModbskPrecon) {
  // Input: poly in basis {q U Bsk}
  // Output: approximateFloor(t/q*poly) in basis Bsk

  // --------------------- step 3 ---------------------
  // approximate rounding

  size_t numQ = moduliQ.size();
  size_t numBsk = moduliBsk.size();

  uint32_t n = GetLength();

  // Twist xi by t*(q/qi)^-1 mod qi
  NativeInteger *txiqiDivqModqi = new NativeInteger[n * numBsk];

  for (uint32_t i = 0; i < numQ; i++) {
    const NativeInteger &currenttqDivqiModqi = tQHatInvModq[i];
    const NativeInteger &currenttqDivqiModqiPrecon = tQHatInvModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      // multiply by t*(q/qi)^-1 mod qi
      m_vectors[i][k].ModMulFastConstEq(currenttqDivqiModqi, moduliQ[i],
                                        currenttqDivqiModqiPrecon);
    }
  }

  vector<NativeInteger> mu(numBsk);
  for (usint j = 0; j < numBsk; j++) {
    mu[j] = moduliBsk[j].ComputeMu();
  }

  for (uint32_t j = 0; j < numBsk; j++) {
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      for (uint32_t i = 0; i < numQ; i++) {
        const NativeInteger &InvqiModBjValue = qInvModbsk[i][j];
        NativeInteger &xi = m_vectors[i][k];
        txiqiDivqModqi[j * n + k].ModAddFastEq(
            xi.ModMulFast(InvqiModBjValue, moduliBsk[j], mu[j]), moduliBsk[j]);
      }
    }
  }

  // now we have FastBaseConv( |t*ct|q, q, Bsk ) in txiqiDivqModqi

  for (uint32_t i = 0; i < numBsk; i++) {
    const NativeInteger &currenttDivqModBski = tQInvModbsk[i];
    const NativeInteger &currenttDivqModBskiPrecon = tQInvModbskPrecon[i];
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      // Not worthy to use lazy reduction here
      m_vectors[i + numQ][k].ModMulFastConstEq(
          currenttDivqModBski, moduliBsk[i], currenttDivqModBskiPrecon);
      m_vectors[i + numQ][k].ModSubFastEq(txiqiDivqModqi[i * n + k],
                                          moduliBsk[i]);
    }
  }
  delete[] txiqiDivqModqi;
  txiqiDivqModqi = nullptr;
}
#endif

#if defined(HAVE_INT128) && NATIVEINT == 64
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvSK(
    const std::vector<NativeInteger> &moduliQ,
    const std::vector<DoubleNativeInt> &modqBarrettMu,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &BHatInvModb,
    const std::vector<NativeInteger> &BHatInvModbPrecon,
    const std::vector<NativeInteger> &BHatModmsk,
    const NativeInteger &BInvModmsk, const NativeInteger &BInvModmskPrecon,
    const std::vector<std::vector<NativeInteger>> &BHatModq,
    const std::vector<NativeInteger> &BModq,
    const std::vector<NativeInteger> &BModqPrecon) {
  // Input: poly in basis Bsk
  // Output: poly in basis q

  // FastBaseconv(x, B, q)
  size_t sizeQ = moduliQ.size();
  size_t sizeBsk = moduliBsk.size();

  uint32_t n = GetLength();

  for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
    const NativeInteger &currentBDivBiModBi = BHatInvModb[i];
    const NativeInteger &currentBDivBiModBiPrecon = BHatInvModbPrecon[i];
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      m_vectors[sizeQ + i][k].ModMulFastConstEq(
          currentBDivBiModBi, moduliBsk[i], currentBDivBiModBiPrecon);
    }
  }

  for (uint32_t j = 0; j < sizeQ; j++) {
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      DoubleNativeInt result = 0;
      for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
        const NativeInteger &currentBDivBiModqj = BHatModq[i][j];
        const NativeInteger &xi = m_vectors[sizeQ + i][k];
        result += Mul128(xi.ConvertToInt(), currentBDivBiModqj.ConvertToInt());
      }
      m_vectors[j][k] = BarrettUint128ModUint64(
          result, moduliQ[j].ConvertToInt(), modqBarrettMu[j]);
    }
  }

  // calculate alphaskx
  // FastBaseConv(x, B, msk)
  NativeInteger *alphaskxVector = new NativeInteger[n];
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    DoubleNativeInt result = 0;
    for (uint32_t i = 0; i < sizeBsk - 1; i++) {
      const NativeInteger &currentBDivBiModmsk = BHatModmsk[i];
      result += Mul128(m_vectors[sizeQ + i][k].ConvertToInt(),
                       currentBDivBiModmsk.ConvertToInt());
    }
    alphaskxVector[k] =
        BarrettUint128ModUint64(result, moduliBsk[sizeBsk - 1].ConvertToInt(),
                                modbskBarrettMu[sizeBsk - 1]);
  }

  // subtract xsk
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    alphaskxVector[k] = alphaskxVector[k].ModSubFast(
        m_vectors[sizeQ + sizeBsk - 1][k], moduliBsk[sizeBsk - 1]);
    alphaskxVector[k].ModMulFastConstEq(BInvModmsk, moduliBsk[sizeBsk - 1],
                                        BInvModmskPrecon);
  }

  // do (m_vector - alphaskx*M) mod q
  NativeInteger mskDivTwo = moduliBsk[sizeBsk - 1] / 2;
  for (uint32_t i = 0; i < sizeQ; i++) {
    const NativeInteger &currentBModqi = BModq[i];
    const NativeInteger &currentBModqiPrecon = BModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      NativeInteger alphaskBModqi = alphaskxVector[k];
      if (alphaskBModqi > mskDivTwo)
        alphaskBModqi =
            alphaskBModqi.ModSubFast(moduliBsk[sizeBsk - 1], moduliQ[i]);

      alphaskBModqi.ModMulFastConstEq(currentBModqi, moduliQ[i],
                                      currentBModqiPrecon);
      m_vectors[i][k] = m_vectors[i][k].ModSubFast(alphaskBModqi, moduliQ[i]);
    }
  }

  // drop extra vectors

  // this code died on mac;
  // need to be smarter about use of erase, and bounds...
  //  for (uint32_t i = 0; i < numBsk; i++)
  //      m_vectors.erase (m_vectors.begin() + numq + i);

  // erase vectors from begin() + numq to begin() + numq + numBsk
  // make sure beginning and end are inside the vector :)
  if (sizeQ < m_vectors.size()) {
    auto starti = m_vectors.begin() + sizeQ;
    if (starti + sizeBsk >= m_vectors.end())
      m_vectors.erase(starti, m_vectors.end());
    else
      m_vectors.erase(starti, starti + sizeBsk);
  }

  delete[] alphaskxVector;
  alphaskxVector = nullptr;
}
#else
template <typename VecType>
void DCRTPolyImpl<VecType>::FastBaseConvSK(
    const std::vector<NativeInteger> &moduliQ,
    const std::vector<DoubleNativeInt> &modqBarrettMu,
    const std::vector<NativeInteger> &moduliBsk,
    const std::vector<DoubleNativeInt> &modbskBarrettMu,
    const std::vector<NativeInteger> &BHatInvModb,
    const std::vector<NativeInteger> &BHatInvModbPrecon,
    const std::vector<NativeInteger> &BHatModmsk,
    const NativeInteger &BInvModmsk, const NativeInteger &BInvModmskPrecon,
    const std::vector<std::vector<NativeInteger>> &BHatModq,
    const std::vector<NativeInteger> &BModq,
    const std::vector<NativeInteger> &BModqPrecon) {
  // Input: poly in basis Bsk
  // Output: poly in basis q

  // FastBaseconv(x, B, q)
  size_t sizeQ = moduliQ.size();
  size_t sizeBsk = moduliBsk.size();

  uint32_t n = GetLength();

  for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
    const NativeInteger &currentBDivBiModBi = BHatInvModb[i];
    const NativeInteger &currentBDivBiModBiPrecon = BHatInvModbPrecon[i];
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      m_vectors[sizeQ + i][k].ModMulFastConstEq(
          currentBDivBiModBi, moduliBsk[i], currentBDivBiModBiPrecon);
    }
  }

  vector<NativeInteger> mu(sizeQ);
  for (usint j = 0; j < sizeQ; j++) {
    mu[j] = moduliQ[j].ComputeMu();
  }

  for (uint32_t j = 0; j < sizeQ; j++) {
#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      m_vectors[j][k] = NativeInteger(0);
      for (uint32_t i = 0; i < sizeBsk - 1; i++) {  // exclude msk residue
        const NativeInteger &currentBDivBiModqj = BHatModq[i][j];
        const NativeInteger &xi = m_vectors[sizeQ + i][k];
        m_vectors[j][k].ModAddFastEq(
            xi.ModMulFast(currentBDivBiModqj, moduliQ[j], mu[j]), moduliQ[j]);
      }
    }
  }

  NativeInteger muBsk = moduliBsk[sizeBsk - 1].ComputeMu();

  // calculate alphaskx
  // FastBaseConv(x, B, msk)
  NativeInteger *alphaskxVector = new NativeInteger[n];
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    for (uint32_t i = 0; i < sizeBsk - 1; i++) {
      const NativeInteger &currentBDivBiModmsk = BHatModmsk[i];
      // changed from ModAddFastEq to ModAddEq
      alphaskxVector[k].ModAddEq(
          m_vectors[sizeQ + i][k].ModMul(currentBDivBiModmsk,
                                         moduliBsk[sizeBsk - 1], muBsk),
          moduliBsk[sizeBsk - 1]);
    }
  }

  // subtract xsk
#pragma omp parallel for
  for (uint32_t k = 0; k < n; k++) {
    alphaskxVector[k] = alphaskxVector[k].ModSubFast(
        m_vectors[sizeQ + sizeBsk - 1][k], moduliBsk[sizeBsk - 1]);
    alphaskxVector[k].ModMulFastConstEq(BInvModmsk, moduliBsk[sizeBsk - 1],
                                        BInvModmskPrecon);
  }

  // do (m_vector - alphaskx*M) mod q
  NativeInteger mskDivTwo = moduliBsk[sizeBsk - 1] / 2;
  for (uint32_t i = 0; i < sizeQ; i++) {
    const NativeInteger &currentBModqi = BModq[i];
    const NativeInteger &currentBModqiPrecon = BModqPrecon[i];

#pragma omp parallel for
    for (uint32_t k = 0; k < n; k++) {
      NativeInteger alphaskBModqi = alphaskxVector[k];
      if (alphaskBModqi > mskDivTwo)
        alphaskBModqi =
            alphaskBModqi.ModSubFast(moduliBsk[sizeBsk - 1], moduliQ[i]);

      alphaskBModqi.ModMulFastConstEq(currentBModqi, moduliQ[i],
                                      currentBModqiPrecon);
      m_vectors[i][k] = m_vectors[i][k].ModSubFast(alphaskBModqi, moduliQ[i]);
    }
  }

  // drop extra vectors

  // this code died on mac;
  // need to be smarter about use of erase, and bounds...
  //  for (uint32_t i = 0; i < numBsk; i++)
  //      m_vectors.erase (m_vectors.begin() + numq + i);

  // erase vectors from begin() + numq to begin() + numq + numBsk
  // make sure beginning and end are inside the vector :)
  if (sizeQ < m_vectors.size()) {
    auto starti = m_vectors.begin() + sizeQ;
    if (starti + sizeBsk >= m_vectors.end())
      m_vectors.erase(starti, m_vectors.end());
    else
      m_vectors.erase(starti, starti + sizeBsk);
  }

  delete[] alphaskxVector;
  alphaskxVector = nullptr;
}
#endif

/*Switch format calls IlVector2n's switchformat*/
template <typename VecType>
void DCRTPolyImpl<VecType>::SwitchFormat() {
  if (m_format == Format::COEFFICIENT) {
    m_format = Format::EVALUATION;
  } else {
    m_format = Format::COEFFICIENT;
  }

#pragma omp parallel for
  for (usint i = 0; i < m_vectors.size(); i++) {
    m_vectors[i].SwitchFormat();
  }
}

#ifdef OUT
template <typename VecType>
void DCRTPolyImpl<VecType>::SwitchModulus(const Integer &modulus,
                                          const Integer &rootOfUnity) {
  m_modulus = Integer::ONE;
  for (usint i = 0; i < m_vectors.size(); ++i) {
    auto mod = modulus % Integer((*m_params)[i]->GetModulus().ConvertToInt());
    auto root =
        rootOfUnity % Integer((*m_params)[i]->GetModulus().ConvertToInt());
    m_vectors[i].SwitchModulus(mod.ConvertToInt(), root.ConvertToInt());
    m_modulus = m_modulus * mod;
  }
}
#endif

template <typename VecType>
void DCRTPolyImpl<VecType>::SwitchModulusAtIndex(usint index,
                                                 const Integer &modulus,
                                                 const Integer &rootOfUnity) {
  if (index > m_vectors.size() - 1) {
    std::string errMsg;
    errMsg = "DCRTPolyImpl is of size = " + std::to_string(m_vectors.size()) +
             " but SwitchModulus for tower at index " + std::to_string(index) +
             "is called.";
    PALISADE_THROW(math_error, errMsg);
  }

  m_vectors[index].SwitchModulus(PolyType::Integer(modulus.ConvertToInt()),
                                 PolyType::Integer(rootOfUnity.ConvertToInt()));
  m_params->RecalculateModulus();
}

template <typename VecType>
bool DCRTPolyImpl<VecType>::InverseExists() const {
  for (usint i = 0; i < m_vectors.size(); i++) {
    if (!m_vectors[i].InverseExists()) return false;
  }
  return true;
}

template <typename VecType>
double DCRTPolyImpl<VecType>::Norm() const {
  PolyLargeType poly(CRTInterpolate());
  return poly.Norm();
}

template <typename VecType>
std::ostream &operator<<(std::ostream &os, const DCRTPolyImpl<VecType> &p) {
  // TODO(gryan): Standardize this printing so it is like other poly's
  os << "---START PRINT DOUBLE CRT-- WITH SIZE" << p.m_vectors.size()
     << std::endl;
  for (usint i = 0; i < p.m_vectors.size(); i++) {
    os << "VECTOR " << i << std::endl;
    os << p.m_vectors[i];
  }
  os << "---END PRINT DOUBLE CRT--" << std::endl;
  return os;
}
}  // namespace lbcrypto
