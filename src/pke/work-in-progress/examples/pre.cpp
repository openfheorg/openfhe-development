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
  Demo software for multiparty proxy reencryption operations for various schemes
 */

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

#include "palisade.h"
#include "cryptocontexthelper.h"

using namespace lbcrypto;

int run_demo_pre(std::string input);

void usage() {
  std::cout << "-i (optional) run interactively to select parameters"
            << std::endl
            << " <PARAMETER SET> to run with that parameter set" << std::endl;
}

// trim whitespace from string from start (in place)
// code from to https://stackoverflow.com/a/44973498/524503
static inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                  [](int ch) { return !std::isspace(ch); }));
}
// trim from end (in place)
static inline void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(),
                       [](int ch) { return !std::isspace(ch); })
              .base(),
          s.end());
}
// trim from both ends (in place)
static inline void trim(std::string &s) {
  ltrim(s);
  rtrim(s);
}

int main(int argc, char *argv[]) {
  bool interactive = false;
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  std::string input = "";
  std::string progname = *argv;
  while (argc-- > 1) {
    std::string arg(*++argv);
    if (arg == "-help" || arg == "-?") {
      usage();
      return 0;
    } else if (arg == "-i") {
      interactive = true;

    } else if (arg[0] == '-') {
      usage();
      return (0);

    } else {
      input = arg;
    }
  }
  std::cout << "This code shows how to use schemes and pre-computed parameters "
               "for those schemes that can be selected during run-time. "
            << std::endl;
  if (input.compare("") == 0) {
    std::cout << "\nThis code demonstrates the use of multiple schemes for "
                 "basic proxy-re-encryption operations. ";
    std::cout
        << "This code shows how to use schemes and pre-computed parameters for "
           "those schemes can be selected during run-time. ";
    std::cout << "In this demonstration we encrypt data and then proxy "
                 "re-encrypt it. ";

    std::cout << "\nThis demo can be run as " << progname << " <PARAMETER SET> "
              << std::endl;
    std::cout << "\nRunning this demo as " << progname
              << " ALL or without any parameters will run all schemes "
              << std::endl;
    std::cout << "\nRunning this demo as " << progname
              << " -i enters interactive mode " << std::endl;
  }
  std::cout << "time using Math backend " << MATHBACKEND << std::endl;

  std::ostringstream stream;
  CryptoContextHelper::printParmSetNamesByFilter(stream, "PRE");
  std::string parameter_set_list = stream.str();

  // tokenize the string that lists parameters, separated by commas
  char delim = ',';  // our delimiter
  std::istringstream ss(stream.str());
  std::string token;

  std::vector<std::string> tokens;
  while (std::getline(ss, token, delim)) {
    // remove any leading or trailing whitespace from token
    trim(token);
    tokens.push_back(token);
  }

  if (interactive) {
    std::cout << "Choose parameter set: " << parameter_set_list;
    std::cout << "or enter ALL to run every set." << std::endl;
    input = "";
    std::cin >> input;

  } else if (input.compare("") == 0) {
    // input can be specified on the command line
    input = "ALL";
  }

  if (input.compare("ALL") != 0) {  // run a particular parameter set
    // validate input
    bool valid = false;
    for (std::string param : tokens) {
      if (input.compare(param) == 0) {
        valid = true;
        break;
      }
    }
    if (!valid) {
      std::cout << "Error: " << input << " is not a valid parameter set."
                << std::endl;
      std::cout << "Valid sets are: " << parameter_set_list;
      exit(1);
    }
    std::cout << "Running using parameter set: " << input << std::endl;

    int rc = run_demo_pre(input);

    if (rc) {  // there could be an error
      exit(1);
    }
  } else {  // run ALL parameter sets
    // tokens contain the array of parameter name strings
    for (std::string param : tokens) {
      std::cout << "Running using parameter set: " << param << std::endl;
      int rc = run_demo_pre(param);

      if (rc) {  // there could be an error
        exit(1);
      }
    }
  }
  exit(0);  // successful return
}

int run_demo_pre(std::string input) {
  // Generate parameters.
  double diff, start, finish;

  start = currentDateTime();

  CryptoContext<Poly> cryptoContext = CryptoContextHelper::getNewContext(input);
  if (!cryptoContext) {
    std::cout << "Error using parameter set:" << input << std::endl;
    return 1;
  }

  finish = currentDateTime();
  diff = finish - start;

  std::cout << "\nParam generation time: "
       << "\t" << diff << " ms" << std::endl;

  // Turn on features
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);
  cryptoContext->Enable(PRE);

  std::cout << "p = "
            << cryptoContext->GetCryptoParameters()->GetPlaintextModulus()
            << std::endl;
  std::cout << "n = "
            << cryptoContext->GetCryptoParameters()
                       ->GetElementParams()
                       ->GetCyclotomicOrder() /
                   2
            << std::endl;
  std::cout << "log2 q = "
            << log2(cryptoContext->GetCryptoParameters()
                        ->GetElementParams()
                        ->GetModulus()
                        .ConvertToDouble())
            << std::endl;
  std::cout << "r = " << cryptoContext->GetCryptoParameters()->GetRelinWindow()
            << std::endl;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  // Initialize Key Pair Containers
  KeyPair<Poly> keyPair1;

  std::cout << "\nRunning key generation (used for source data)..."
            << std::endl;

  start = currentDateTime();

  keyPair1 = cryptoContext->KeyGen();

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Key generation time: "
       << "\t" << diff << " ms" << std::endl;

  if (!keyPair1.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts = {1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1};
  Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  start = currentDateTime();

  auto ciphertext1 = cryptoContext->Encrypt(keyPair1.publicKey, plaintext);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Encryption time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Decryption of Ciphertext
  ////////////////////////////////////////////////////////////

  Plaintext plaintextDec1;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair1.secretKey, ciphertext1, &plaintextDec1);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Decryption time: "
       << "\t" << diff << " ms" << std::endl;

  // std::cin.get();

  plaintextDec1->SetLength(plaintext->GetLength());

  std::cout << "\n Original Plaintext: \n";
  std::cout << plaintext << std::endl;

  std::cout << "\n Resulting Decryption of Ciphertext before Re-Encryption: \n";
  std::cout << plaintextDec1 << std::endl;

  std::cout << "\n";

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  // Initialize Key Pair Containers
  KeyPair<Poly> keyPair2;

  std::cout << "Running key generation (used for source data)..." << std::endl;

  start = currentDateTime();

  keyPair2 = cryptoContext->KeyGen();

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Key generation time: "
       << "\t" << diff << " ms" << std::endl;

  if (!keyPair2.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Perform the proxy re-encryption key generation operation.
  // This generates the keys which are used to perform the key switching.
  ////////////////////////////////////////////////////////////

  std::cout << "\n"
            << "Generating proxy re-encryption key..." << std::endl;

  EvalKey<Poly> reencryptionKey12;

  start = currentDateTime();

  reencryptionKey12 =
      cryptoContext->ReKeyGen(keyPair2.publicKey, keyPair1.secretKey);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Key generation time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Re-Encryption
  ////////////////////////////////////////////////////////////

  start = currentDateTime();

  auto ciphertext2 = cryptoContext->ReEncrypt(reencryptionKey12, ciphertext1);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Re-Encryption time: "
       << "\t" << diff << " ms" << std::endl;

  ////////////////////////////////////////////////////////////
  // Decryption of Ciphertext
  ////////////////////////////////////////////////////////////

  Plaintext plaintextDec2;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair2.secretKey, ciphertext2, &plaintextDec2);

  finish = currentDateTime();
  diff = finish - start;
  std::cout << "Decryption time: "
       << "\t" << diff << " ms" << std::endl;

  plaintextDec2->SetLength(plaintext->GetLength());

  std::cout << "\n Original Plaintext: \n";
  std::cout << plaintext << std::endl;

  std::cout << "\n Resulting Decryption of Ciphertext before Re-Encryption: \n";
  std::cout << plaintextDec1 << std::endl;

  std::cout << "\n Resulting Decryption of Ciphertext after Re-Encryption: \n";
  std::cout << plaintextDec2 << std::endl;

  std::cout << "\n";

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  std::cout << "Execution Completed." << std::endl;

  return 0;
}
