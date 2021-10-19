// @file serial.h Serialization utilities.
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

#ifndef LBCRYPTO_SERIAL_H
#define LBCRYPTO_SERIAL_H

// TODO (dsuponit): purge the headers below and combine #pragma for GNU and clang
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#ifndef CEREAL_RAPIDJSON_HAS_STDSTRING
#define CEREAL_RAPIDJSON_HAS_STDSTRING 1
#endif
#ifndef CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS
#define CEREAL_RAPIDJSON_HAS_CXX11_RVALUE_REFS 1
#endif
#define CEREAL_RAPIDJSON_HAS_CXX11_NOEXCEPT 0

#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-private-field"
#endif

#include "utils/sertype.h"

#include "cereal/archives/portable_binary.hpp"
#include "cereal/archives/json.hpp"
#include "cereal/cereal.hpp"
#include "cereal/types/map.hpp"
#include "cereal/types/memory.hpp"
#include "cereal/types/polymorphic.hpp"
#include "cereal/types/string.hpp"
#include "cereal/types/vector.hpp"

#ifdef __GNUC__
#if __GNUC__ >= 8
#pragma GCC diagnostic pop
#endif
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif


namespace lbcrypto {

	namespace Serial {
		//========================== BINARY serialization ==========================
		/**
		 * Serialize an object
		 * @param obj - object to serialize
		 * @param stream - Stream to serialize to
		 * @param sertype - type of serialization; default is BINARY
		 */
		template <typename T>
		void Serialize(const T& obj, std::ostream& stream, const SerType::SERBINARY& st) {
			cereal::PortableBinaryOutputArchive archive(stream);
			archive(obj);
		}

		/**
		 * Deserialize an object
		 * @param obj - object to deserialize into
		 * @param stream - Stream to deserialize from
		 * @param sertype - type of de-serialization; default is BINARY
		 */
		template <typename T>
		void Deserialize(T& obj, std::istream& stream, const SerType::SERBINARY& st) {
			cereal::PortableBinaryInputArchive archive(stream);
			archive(obj);
		}

		template <typename T>
		bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERBINARY& sertype) {
			std::ofstream file(filename, std::ios::out | std::ios::binary);
			if (file.is_open()) {
				Serial::Serialize(obj, file, sertype);
				file.close();
				return true;
			}
			return false;
		}

		template <typename T>
		bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERBINARY& sertype) {
			std::ifstream file(filename, std::ios::in | std::ios::binary);
			if (file.is_open()) {
				Serial::Deserialize(obj, file, sertype);
				file.close();
				return true;
			}
			return false;
		}

		//========================== JSON serialization ==========================
		/**
		 * Serialize an object
		 * @param obj - object to serialize
		 * @param stream - Stream to serialize to
		 * @param sertype - type of serialization; default is BINARY
		 */
		template <typename T>
		void Serialize(const T& obj, std::ostream& stream, const SerType::SERJSON& ser) {
			cereal::JSONOutputArchive archive(stream);
			archive(obj);
		}

		/**
		 * Deserialize an object
		 * @param obj - object to deserialize into
		 * @param stream - Stream to deserialize from
		 * @param sertype - type of serialization; default is BINARY
		 */
		template <typename T>
		void Deserialize(T& obj, std::istream& stream, const SerType::SERJSON& ser) {
			cereal::JSONInputArchive archive(stream);
			archive(obj);
		}

		template <typename T>
		bool SerializeToFile(const std::string& filename, const T& obj, const SerType::SERJSON& sertype) {
			std::ofstream file(filename, std::ios::out | std::ios::binary);
			if (file.is_open()) {
				Serial::Serialize(obj, file, sertype);
				file.close();
				return true;
			}
			return false;
		}

		template <typename T>
		bool DeserializeFromFile(const std::string& filename, T& obj, const SerType::SERJSON& sertype) {
			std::ifstream file(filename, std::ios::in | std::ios::binary);
			if (file.is_open()) {
				Serial::Deserialize(obj, file, sertype);
				file.close();
				return true;
			}
			return false;
		}

		/**
		 * SerializeToString - serialize the object to a JSON string and return the
		 * string
		 * @param t - any serializable object
		 * @return JSON string
		 */
		template <typename T>
		std::string SerializeToString(const T& t) {
			std::stringstream s;
			Serialize(t, s, SerType::JSON);
			return s.str();
		}


	}  // namespace Serial

}  // namespace lbcrypto

#endif
