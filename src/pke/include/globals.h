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
  config.h created by Matthew Triplett to add a configuration parameter
  which allows toggling of CRT precomputations during deserialization of a CryptoContext.
 */

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

namespace lbcrypto {
/**
     * PrecomputeCRTTablesAfterDeserializaton() will be executed during CryptoContext deserialization.
     * Deserializing without this precomputation can speed up the procedure by a factor of 100.
     * function's return values:
     * true (default value): PrecomputeCRTTables() will be executed during deserialization
     * false:                PrecomputeCRTTables() will not be executed during deserialization
     */
bool PrecomputeCRTTablesAfterDeserializaton();

/**
     * Calling EnablePrecomputeCRTTablesAfterDeserializaton() and DisablePrecomputeCRTTablesAfterDeserializaton()
     * changes the boolean value returned by PrecomputeCRTTablesAfterDeserializaton()
     */
void EnablePrecomputeCRTTablesAfterDeserializaton();
void DisablePrecomputeCRTTablesAfterDeserializaton();

}  // namespace lbcrypto

#endif  // __GLOBALS_H__
