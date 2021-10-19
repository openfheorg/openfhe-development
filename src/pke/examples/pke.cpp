// @file pke.cpp - Example of public key encryption.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
//
// @section DESCRIPTION
// Demo software for PKE multiparty operations for various schemes.

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

#include "palisade.h"

using namespace std;
using namespace lbcrypto;

int run_demo_pke(string input);

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
  ////////////////////////////////////////////////////////////
  // Set-up of parameters
  ////////////////////////////////////////////////////////////
  bool interactive = false;
  string input = "";
  string progname = *argv;
  while (argc-- > 1) {
    string arg(*++argv);

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
                 "basic public key encryption operations. ";
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
  CryptoContextHelper::printParmSetNamesByExcludeFilters(stream,
                                                         {"BFVrns", "CKKS"});
  string parameter_set_list = stream.str();

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
    std::cin >> input;

  } else if (input.compare("") ==
             0) {  // input can be specified on the command line
    input = "ALL";
  }

  if (input.compare("ALL") != 0) {  // run a particular parameter set
    // validate input
    bool valid = false;
    for (string param : tokens) {
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

    int rc = run_demo_pke(input);

    if (rc) {  // there could be an error
      exit(1);
    }
  } else {  // run ALL parameter sets
    // tokens contain the array of parameter name strings
    for (string param : tokens) {
      std::cout << "Running using parameter set: " << param << std::endl;
      int rc = run_demo_pke(param);

      if (rc) {  // there could be an error
        // exit(1);
      }
    }
  }
  exit(0);  // successful return
}

int run_demo_pke(string input) {
  // Generate parameters.
  double diff, start, finish;

  start = currentDateTime();

  CryptoContext<Poly> cryptoContext = CryptoContextHelper::getNewContext(input);
  if (!cryptoContext) {
    cout << "Error on " << input << endl;
    return 1;
  }

  finish = currentDateTime();
  diff = finish - start;

  cout << "Param generation time: "
       << "\t" << diff << " ms" << endl;

  // Turn on features
  cryptoContext->Enable(ENCRYPTION);

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

  // Initialize Public Key Containers
  LPKeyPair<Poly> keyPair;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  std::cout << "Running key generation (used for source data)..." << std::endl;

  start = currentDateTime();

  keyPair = cryptoContext->KeyGen();

  finish = currentDateTime();
  diff = finish - start;
  cout << "Key generation time: "
       << "\t" << diff << " ms" << endl;

  if (!keyPair.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts = {1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0};
  Plaintext plaintext = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts);

  ////////////////////////////////////////////////////////////
  // Encryption
  ////////////////////////////////////////////////////////////

  Ciphertext<Poly> ciphertext;

  start = currentDateTime();

  ciphertext = cryptoContext->Encrypt(keyPair.publicKey, plaintext);

  finish = currentDateTime();
  diff = finish - start;
  cout << "Encryption time: "
       << "\t" << diff << " ms" << endl;

  ////////////////////////////////////////////////////////////
  // Decryption of Ciphertext
  ////////////////////////////////////////////////////////////

  Plaintext plaintextDec;

  start = currentDateTime();

  cryptoContext->Decrypt(keyPair.secretKey, ciphertext, &plaintextDec);

  finish = currentDateTime();
  diff = finish - start;
  cout << "Decryption time: "
       << "\t" << diff << " ms" << endl;

  plaintextDec->SetLength(plaintext->GetLength());

  if (*plaintext != *plaintextDec) cout << "Decryption failed!" << endl;

  cout << "\n Original Plaintext: \n";
  cout << *plaintext << endl;

  cout << "\n Resulting Decryption of Ciphertext: \n";
  cout << *plaintextDec << endl;

  cout << "\n";

  ////////////////////////////////////////////////////////////
  // Done
  ////////////////////////////////////////////////////////////

  std::cout << "Execution Completed." << std::endl;

  return 0;
}
