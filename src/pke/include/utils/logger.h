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

#ifndef _LOGGER_H_
#define _LOGGER_H_

#include "logger-impl.h"

/***
 * Logging APIs to be used in the code are defined here. They are:
 *
 * LOG_DEBUG_ALL(msg) - prints everything
 * LOG_DEBUG_3(msg)   - prints more debug trace than for DEBUG_2_LEVEL
 * LOG_DEBUG_2(msg)   - prints more debug trace than for DEBUG_1_LEVEL
 * LOG_DEBUG_1(msg)   - prints some debug trace
 * LOG_INFO(msg)
 * LOG_WARN(msg)
 * LOG_ERR(msg)
 * LOG_FATAL(msg)
***/

#if LOG_LEVEL < DEBUG_ALL_LEVEL
	#define LOG_DEBUG_ALL(msg) ((void)0)
#else
	#define LOG_DEBUG_ALL(msg) LOG.DebugAll(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL < DEBUG_3_LEVEL
	#define LOG_DEBUG_3(msg) ((void)0)
#else
	#define LOG_DEBUG_3(msg) LOG.Debug3(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL < DEBUG_2_LEVEL
	#define LOG_DEBUG_2(msg) ((void)0)
#else
	#define LOG_DEBUG_2(msg) LOG.Debug2(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL < DEBUG_1_LEVEL
	#define LOG_DEBUG_1(msg) ((void)0)
#else
	#define LOG_DEBUG_1(msg) LOG.Debug1(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL<INFO_LEVEL
	#define LOG_INFO(msg) ((void)0)
#else
	#define LOG_INFO(msg) LOG.Info(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL<WARN_LEVEL
	#define LOG_WARN(msg) ((void)0)
#else
	#define LOG_WARN(msg) LOG.Warning(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL<ERR_LEVEL
	#define LOG_ERR(msg) ((void)0)
#else
	#define LOG_ERR(msg) LOG.Error(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#if LOG_LEVEL<FATAL_LEVEL
	#define LOG_FATAL(msg) ((void)0)
#else
	#define LOG_FATAL(msg) LOG.FatalError(msg, __FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif

#endif
