/***
 * © 2020 Duality Technologies, Inc. All rights reserved.
 * This is a proprietary software product of Duality Technologies, Inc. protected under copyright laws
 * and international copyright treaties, patent law, trade secret law and other intellectual property
 * rights of general applicability.
 * Any use of this software is strictly prohibited absent a written agreement executed by Duality
 * Technologies, Inc., which provides certain limited rights to use this software.
 * You may not copy, distribute, make publicly available, publicly perform, disassemble, de-compile or
 * reverse engineer any part of this software, breach its security, or circumvent, manipulate, impair or
 * disrupt its operation.
 ***/
/**
 * @file serial.h Serialization utilities.
 */ 
#ifndef LBCRYPTO_DUALITY_SERIAL_H
#define LBCRYPTO_DUALITY_SERIAL_H

#include <memory>
#include <string>
#include <istream>

#include "utils/sertype.h"

namespace lbcrypto {

template<typename Element>
class CryptoContextImpl;

namespace Serial
{

	/**
	 * Deserialize a CryptoContext as a special case
	 * @param obj - CryptoContext to deserialize into
	 * @param stream - Stream to deserialize from
	 * @param sertype - binary serialization
	 */
	template<typename T>
	static void
	Deserialize(std::shared_ptr<CryptoContextImpl<T>>& obj, std::istream& stream, const SerType::SERBINARY& st);

	/**
	 * Deserialize a CryptoContext as a special case
	 * @param obj - CryptoContext to deserialize into
	 * @param stream - Stream to deserialize from
	 * @param sertype - JSON serialization
	 */
	template<typename T>
	static void
	Deserialize(std::shared_ptr<CryptoContextImpl<T>>& obj, std::istream& stream, const SerType::SERJSON& ser);

	template <typename T>
	static bool
	SerializeToFile(std::string filename, const std::shared_ptr<CryptoContextImpl<T>>& obj, const SerType::SERJSON& ser);

	template <typename T>
	static bool
	DeserializeFromFile(std::string filename, std::shared_ptr<CryptoContextImpl<T>>& obj, const SerType::SERJSON& ser);

	template <typename T>
	static bool
	SerializeToFile(std::string filename, const std::shared_ptr<CryptoContextImpl<T>>& obj, const SerType::SERBINARY& ser);

	template <typename T>
	static bool
	DeserializeFromFile(std::string filename, std::shared_ptr<CryptoContextImpl<T>>& obj, const SerType::SERBINARY& ser);

}

}

#endif
