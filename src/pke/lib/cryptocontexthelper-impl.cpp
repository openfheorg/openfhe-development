// @file cryptocontexthelper-impl.cpp - cryptocontext helper class
// implementation
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

#include "palisade.h"

#include "cryptocontext.h"
#include "cryptocontextgen.h"
#include "cryptocontexthelper.h"
#include "utils/parmfactory.h"

namespace lbcrypto {

static bool getValueForName(const map<string, string>& allvals,
                            const string key, string& value) {
  map<string, string>::const_iterator it = allvals.find(key);
  if (it == allvals.end()) {
    std::cerr << key << " element is missing" << std::endl;
    return false;
  }

  value = it->second;
  return true;
}

template <typename Element>
static CryptoContext<Element> buildContextFromSerialized(
    const map<string, string>& s, shared_ptr<typename Element::Params> parms,
    EncodingParams ep = 0) {
  std::string parmtype;
  std::string plaintextModulus;
  std::string ring;
  std::string modulus;
  std::string rootOfUnity;
  std::string relinWindow;
  std::string stDev;
  std::string secLevel;
  std::string numPrimes;
  std::string scaleExp;
  std::string batchSize;

  if (!getValueForName(s, "parameters", parmtype)) {
    std::cerr << "parameters element is missing" << std::endl;
    return 0;
  }

  if (parmtype == "BFV") {
    if (!getValueForName(s, "plaintextModulus", plaintextModulus) ||
        !getValueForName(s, "securityLevel", secLevel))
      return 0;

    return CryptoContextFactory<Element>::genCryptoContextBFV(
        stoul(plaintextModulus), stof(secLevel), 2, 4, 0, 1, 0);

  } else if (parmtype == "BFVrns") {
    if (!getValueForName(s, "plaintextModulus", plaintextModulus) ||
        !getValueForName(s, "securityLevel", secLevel))
      return 0;

    return CryptoContextFactory<Element>::genCryptoContextBFVrns(
        stoul(plaintextModulus), stof(secLevel), 4, 0, 1, 0);

  } else if (parmtype == "BFVrnsB") {
    if (!getValueForName(s, "plaintextModulus", plaintextModulus) ||
        !getValueForName(s, "securityLevel", secLevel))
      return 0;

    return CryptoContextFactory<Element>::genCryptoContextBFVrnsB(
        stoul(plaintextModulus), stof(secLevel), 4, 0, 1, 0);

  } else if (parmtype == "CKKS") {
    if (!getValueForName(s, "numPrimes", numPrimes) ||
        !getValueForName(s, "scaleExponent", scaleExp) ||
        !getValueForName(s, "relinWindow", relinWindow) ||
        !getValueForName(s, "batchSize", batchSize) ||
        !getValueForName(s, "stDev", stDev)) {
      return 0;
    }

    EncodingParams encodingParams(
        std::make_shared<EncodingParamsImpl>(stoul(scaleExp)));
    encodingParams->SetBatchSize(stoul(batchSize));

    return CryptoContextFactory<Element>::genCryptoContextCKKS(
        parms, encodingParams, stoul(relinWindow), stof(stDev), OPTIMIZED, 1,
        stoul(numPrimes));

  } else if (parmtype == "Null") {
    if (!getValueForName(s, "plaintextModulus", plaintextModulus)) {
      return 0;
    }

    auto ptm = stoul(plaintextModulus);
    return CryptoContextFactory<Element>::genCryptoContextNull(
        parms->GetCyclotomicOrder(), ptm);
  } else {
    PALISADE_THROW(config_error, "Unrecognized parmtype " + parmtype +
                                     " in buildContextFromSerialized");
  }

  return 0;
}

CryptoContext<Poly> CryptoContextHelper::getNewContext(const string& parmset,
                                                       EncodingParams ep) {
  using ParmType = typename Poly::Params;
  using IntType = typename Poly::Integer;

  std::string parmtype;
  std::string ring;
  std::string modulus;
  std::string rootOfUnity;
  std::string scaleExp;

  map<string, map<string, string>>::iterator it =
      CryptoContextParameterSets.find(parmset);

  if (it == CryptoContextParameterSets.end()) {
    return 0;
  }

  if (!getValueForName(it->second, "parameters", parmtype)) {
    std::cerr << "parameters element is missing" << std::endl;
    return 0;
  }

  // BFV uses parm generation so we skip this code for BFV
  shared_ptr<ParmType> parms;
  if ((parmtype != "BFV") && (parmtype != "BFVrns") &&
      (parmtype != "BFVrnsB")) { /* For all schemes besides BFV */
    if ((parmtype == "CKKS")) {  /* For CKKS */
      if (!getValueForName(it->second, "cyclotomicOrder", ring) ||
          !getValueForName(it->second, "scaleExponent", scaleExp)) {
        return 0;
      }

      NativeInteger q = FirstPrime<NativeInteger>(stoul(scaleExp), stoul(ring));
      NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(stoul(ring), q);

      parms = std::make_shared<ParmType>(stoul(ring), IntType(q),
                                         IntType(rootOfUnity));
    } else { /* All other schemes */
      if (!getValueForName(it->second, "ring", ring) ||
          !getValueForName(it->second, "modulus", modulus) ||
          !getValueForName(it->second, "rootOfUnity", rootOfUnity)) {
        return 0;
      }

      parms = std::make_shared<ParmType>(stoul(ring), IntType(modulus),
                                         IntType(rootOfUnity));
    }
  }

  return buildContextFromSerialized<Poly>(it->second, parms, ep);
}

CryptoContext<DCRTPoly> CryptoContextHelper::getNewDCRTContext(
    const string& parmset, usint numTowers, usint primeBits) {
  std::string parmtype;
  std::string ring;
  std::string plaintextModulus;

  map<string, map<string, string>>::iterator it =
      CryptoContextParameterSets.find(parmset);

  if (it == CryptoContextParameterSets.end()) {
    return 0;
  }

  if (!getValueForName(it->second, "parameters", parmtype)) {
    std::cerr << "parameters element is missing" << std::endl;
    return 0;
  }

  // BFV uses parm generation so we skip this code for BFV
  shared_ptr<DCRTPoly::Params> parms;
  if ((parmtype != "BFV") && (parmtype != "BFVrns") &&
      (parmtype != "BFVrnsB")) {
    if (!getValueForName(it->second, "ring", ring) ||
        !getValueForName(it->second, "plaintextModulus", plaintextModulus)) {
      return 0;
    }

    parms = GenerateDCRTParams<DCRTPoly::Integer>(stoul(ring), numTowers,
                                                  primeBits);
  }
  return buildContextFromSerialized<DCRTPoly>(it->second, parms);
}

template <typename Element>
shared_ptr<LPPublicKeyEncryptionScheme<Element>> CreateSchemeGivenName(
    const string& schemeName) {
  if (schemeName == "BFV")
    return std::make_shared<LPPublicKeyEncryptionSchemeBFV<Element>>();

  // return std::make_shared<LPPublicKeyEncryptionSchemeBFVrns<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeBFVrnsB<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeLElementV<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeNull<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeBFV<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeBFVrns<Element>>();
  // return std::make_shared<LPPublicKeyEncryptionSchemeBFVrnsB<Element>>();
  //  };
  //
  //  return SchemeFromName[schemeName];
  else
    return 0;
}

template <typename Element>
CryptoContext<Element> CryptoContextHelper::ContextFromAppProfile(
    const string& sch, PlaintextModulus ptm, usint nA, usint nM, usint nK,
    usint maxD, float secFactor) {
  //
  ////  usint m;
  ////  string q, ru;
  ////  PlaintextModulus p;
  ////
  ////  float secLevel;
  ////  usint qbits;
  ////  usint relinWindow;
  ////  float stdev;
  //
  // #if OLD_ITEM
  //  // an MQP confset specifies all 4 of these
  //  if( setType == "MQP" ) {
  //    m = stoul( cs["m"].GetString() );
  //    q = cs["q"].GetString();
  //    if( cs.HasMember("ru") )
  //      ru = cs["ru"].GetString();
  //    p = stoul( cs["p"].GetString() );
  //
  //    cout << m << endl;
  //    cout << q << endl;
  //    cout << p << endl;
  //    return 0;
  //  }
  //  else if( setType == "MqbitsP" ) {
  //    m = stoul( cs["m"].GetString() );
  //    qbits = stoul( cs["qbits"].GetString() );
  //    p = stoul( cs["p"].GetString() );
  //
  //    // make a prime q of at least qbits in size
  //    cout << m << endl;
  //    cout << qbits << endl;
  //    cout << p << endl;
  //    return 0;
  //  }
  //  else if( setType == "MQgen" ){
  //      secLevel = stof( cs["secLevel"].GetString() );
  //      nA = stoul( cs["numAdds"].GetString() );
  //      nM = stoul( cs["numMults"].GetString() );
  //      nK = stoul( cs["numKS"].GetString() );
  //      p = stoul( cs["p"].GetString() );
  //      qbits = stoul( cs["qbits"].GetString() );
  //      relinWindow = stoul( cs["relinWindow"].GetString() );
  //      stdev = stof( cs["dist"].GetString() );
  //  }
  //  else {
  //    return 0;
  //  }
  // #endif
  //
  //  usint relinWindow;
  //  float dist;
  //
  // if( sch == "BFVrns" ) {
  //    return
  // CryptoContextFactory<Element>::genCryptoContextBFVrns(ptm, secFactor, dist,
  // nA, nM, nK, OPTIMIZED, 5, relinWindow);
  //  }
  //  else {
  //, "BFV", "BFVrns", "FV", "Null"
  return 0;
  //  }
}

// template CryptoContext<Poly>
// CryptoContextHelper::ContextFromAppProfile<Poly>(const string& sch, const
// rapidjson::Value&); template CryptoContext<DCRTPoly>
// CryptoContextHelper::ContextFromAppProfile<DCRTPoly>(const string& sch, const
// rapidjson::Value&);

static void printSet(std::ostream& out, string key, map<string, string>& pset) {
  out << "Parameter set: " << key << std::endl;

  for (const auto& P : pset) {
    out << "  " << P.first << ": " << P.second << std::endl;
  }
}

void CryptoContextHelper::printParmSet(std::ostream& out, string parmset) {
  auto it = CryptoContextParameterSets.find(parmset);
  if (it == CryptoContextParameterSets.end()) {
    out << "Parameter set " << parmset << " is unknown" << std::endl;
  } else {
    printSet(out, it->first, it->second);
  }
}

void CryptoContextHelper::printAllParmSets(std::ostream& out) {
  for (auto S : CryptoContextParameterSets) {
    printSet(out, S.first, S.second);
  }
}

void CryptoContextHelper::printAllParmSetNames(std::ostream& out) {
  map<string, map<string, string>>::iterator it =
      CryptoContextParameterSets.begin();

  out << it->first;

  for (it++; it != CryptoContextParameterSets.end(); it++) {
    out << ", " << it->first;
  }
  out << std::endl;
}

void CryptoContextHelper::printParmSetNamesByFilter(std::ostream& out,
                                                    const string& filter) {
  size_t counter = 0;
  for (const auto& it : CryptoContextParameterSets) {
    if (it.first.find(filter) != string::npos) {
      if (counter == 0)
        out << it.first;
      else
        out << ", " << it.first;
      counter++;
    }
  }
  out << std::endl;
}

void CryptoContextHelper::printParmSetNamesByFilters(
    std::ostream& out, std::initializer_list<std::string> filters) {
  size_t counter = 0;
  for (const auto& it : CryptoContextParameterSets) {
    for (const auto& filter : filters) {
      if (it.first.find(filter) != string::npos) {
        if (counter == 0)
          out << it.first;
        else
          out << ", " << it.first;
        counter++;
        break;
      }
    }
  }
  out << std::endl;
}

void CryptoContextHelper::printParmSetNamesByExcludeFilter(
    std::ostream& out, const string& filter) {
  size_t counter = 0;
  for (const auto& it : CryptoContextParameterSets) {
    if (it.first.find(filter) == string::npos) {
      if (counter == 0)
        out << it.first;
      else
        out << ", " << it.first;
      counter++;
    }
  }
  out << std::endl;
}

void CryptoContextHelper::printParmSetNamesByExcludeFilters(
    std::ostream& out, std::initializer_list<std::string> filters) {
  size_t counter = 0;
  for (const auto& it : CryptoContextParameterSets) {
    bool isFound = false;
    for (const auto& filter : filters) {
      if (it.first.find(filter) != string::npos) {
        isFound = true;
        break;
      }
    }

    if (!isFound) {
      if (counter == 0)
        out << it.first;
      else
        out << ", " << it.first;
      counter++;
    }
  }
  out << std::endl;
}
}  // namespace lbcrypto
