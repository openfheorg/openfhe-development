// @file README.md - describes the process of adding a new scheme.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2021, New Jersey Institute of Technology (NJIT))
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

The following steps describe the process of adding a new scheme "abcde" to Palisade. 
1. Create a new subdirectory ./src/pke/include/scheme/abcde
2. Add the following header files to this folder:
    - abcde.h: includes scheme-specific classes for parameters, algorithms and PublicKeyEncryptionScheme
    - abcde-ser.h: registers new types for serialization
    - cryptocontextparams-abcde.h: defines the parameter class for the "abcde" scheme generation.
        Ex.: class CCParams<CryptoContextABCDE<Element>> : public Params.
        The parameter class is usually derived from Params ( defined in ./src/pke/include/scheme/cryptocontextparams-base.h)
        and may include additional data members with their getters and setters in addition to those
        that can be found in Params.
    - cryptocontext-abcde.h: defines a class with a static function to generate the scheme-specific cryptocontext.
        ATTN: The function name must be "genCryptoContext", the alias "ContextType" must be set and the only input argument to
        the function is an object of the CCParams type. These all are required by GenCryptoContext (defined in
        ./src/pke/include/gen-cryptocontext.h)
    - gen-cryptocontext-abcde-internal.h: defines a function (genCryptoContextABCDEInternal()) which does the actual work
        to generate cryptocontext.
        All values for cryptocontext generation must be taken from the parameter object defined in
        cryptocontextparams-abcde.h and passed to genCryptoContextABCDEInternal().
        All template parameters used in the function must be aliases added in cryptocontext-abcde.h, no actual type names.
        The file should not include any other header than ./src/pke/include/encoding/encodingparams.h.
3. Add the default values for the new parameter class members to ./src/pke/include/scheme/cryptocontextparams-defaults.h.
    - create a new namespace "ABCDE_SCHEME_DEFAULTS". The suffix "_SCHEME_DEFAULTS" is required.
4. Add test cases

See ckks-specific files for more details and ./src/pke/include/gen-cryptocontext.h for comments describing how to call the new API
in client's code.
