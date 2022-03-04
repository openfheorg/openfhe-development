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

#ifndef SRC_PKE_INCLUDE_SCHEME_ALLSCHEME_H_
#define SRC_PKE_INCLUDE_SCHEME_ALLSCHEME_H_

#include "keyswitch/keyswitch-bv.h"
#include "keyswitch/keyswitch-hybrid.h"

#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/bgvrns/bgvrns-parametergeneration.h"
#include "scheme/bgvrns/bgvrns-pke.h"
#include "scheme/bgvrns/bgvrns-pre.h"
#include "scheme/bgvrns/bgvrns-leveledshe.h"
#include "scheme/bgvrns/bgvrns-advancedshe.h"
#include "scheme/bgvrns/bgvrns-multiparty.h"
#include "scheme/bgvrns/bgvrns-scheme.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-parametergeneration.h"
#include "scheme/bfvrns/bfvrns-pke.h"
#include "scheme/bfvrns/bfvrns-pre.h"
#include "scheme/bfvrns/bfvrns-leveledshe.h"
#include "scheme/bfvrns/bfvrns-advancedshe.h"
#include "scheme/bfvrns/bfvrns-multiparty.h"
#include "scheme/bfvrns/bfvrns-scheme.h"

#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-parametergeneration.h"
#include "scheme/ckksrns/ckksrns-pke.h"
#include "scheme/ckksrns/ckksrns-pre.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"
#include "scheme/ckksrns/ckksrns-advancedshe.h"
#include "scheme/ckksrns/ckksrns-multiparty.h"
#include "scheme/ckksrns/ckksrns-scheme.h"

#endif /* SRC_PKE_INCLUDE_SCHEME_ALLSCHEME_H_ */
