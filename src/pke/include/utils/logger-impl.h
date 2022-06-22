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

#ifndef _LOGGER_IMPL_H_
#define _LOGGER_IMPL_H_

#include "config_core.h"
#include <string>
#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>


// do not change the sequence of log levels. Logger's decision whether to print a message is based on it.
// I didn't use enum here on purpose to avoid any mistake
#define FATAL_LEVEL      1
#define ERR_LEVEL        2
#define WARN_LEVEL       3
#define INFO_LEVEL       4
#define DEBUG_1_LEVEL    5 // to print some debug trace
#define DEBUG_2_LEVEL    6 // to print more debug trace than for DEBUG_1_LEVEL
#define DEBUG_3_LEVEL    7 // to print more debug trace than for DEBUG_2_LEVEL
#define DEBUG_ALL_LEVEL 10 // to print everything

#ifndef LOG_LEVEL
    #define LOG_LEVEL WARN_LEVEL // default log level value. usually it is set in CMakeList.txt
#endif

class Logger
{
	std::string fileName;
	std::ostream* output;

	unsigned logLevel;

	Logger() : output(&std::cout), logLevel(LOG_LEVEL) { }

	// getTracePrefix() produces a string to prepend every trace printed to the log including:
	// time, file name, line number in the file and the function name where the trace was printed from
	// Example: "2020-03-11_16:07:50 test.cpp:l.50:main():ERROR: error description"
	inline std::string getTracePrefix(const std::string& fileName, const std::string& functionName, int  lineNumber)
	{
		// get time first
		auto current_time = std::chrono::system_clock::now();
		auto msecs        = std::chrono::duration_cast<std::chrono::milliseconds>(current_time.time_since_epoch()) % 1000;
		auto now          = std::chrono::system_clock::to_time_t(current_time);

		std::stringstream ss;
		ss << std::put_time(std::localtime(&now), "%Y-%m-%d_%X.")
		   << std::setfill('0')
		   << std::setw(3)
		   << msecs.count()
		   << " "
		   << fileName
		   << ":l."
		   << lineNumber
		   << ":"
		   << functionName
		   << "():";

		return ss.str();
	}

public:
	Logger(const Logger&)         = delete; // as for Singleton
	void operator=(const Logger&) = delete; // as for Singleton

	~Logger() {
		if( &std::cout != output )
			delete output;
	}

	// Use the global variable LOG instead of calling getInstance(). LOG is a reference to instance
	static Logger& getInstance() {
		static Logger instance;
		return instance;
	}

	inline unsigned getLogLevel() {
		return logLevel;
	}

	// logToFile() may be called once only. the second attempt to set the output file will throw an exception
	void setLogFile(const std::string& fileName0);

	// FatalError() is to print a fatal error. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_FATAL(msg) instead.
	inline void FatalError(const std::string& message,
						   const std::string& fileName,
						   const std::string& functionName,
						   int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "FATAL: "
				<< message << std::endl;  // unbufferred output
	}
	
	// Error() is to print an error. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_ERR(msg) instead.
	inline void Error(const std::string& message,
					  const std::string& fileName,
					  const std::string& functionName,
					  int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "ERROR: "
				<< message << std::endl;  // unbufferred output
	}
	
	// Warning() is to print a warning. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_WARN(msg) instead.
	inline void Warning(const std::string& message,
					 	const std::string& fileName,
					 	const std::string& functionName,
					 	int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "WARNING: "
				<< message << std::endl;  // unbufferred output
	}
	
	// Info() is to print an information which is not usually needed for the run. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_INFO(msg) instead.
	inline void Info(const std::string& message,
					 const std::string& fileName,
					 const std::string& functionName,
					 int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "INFO: "
				<< message << "\n";  // bufferred output
	}
	
	// Debug() is to print trace useful for debugging purposes. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_DEBUG_1(msg) instead.
	inline void Debug1(const std::string& message,
					  const std::string& fileName,
					  const std::string& functionName,
					  int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "DEBUG_1: "
				<< message << "\n";  // bufferred output
	}

	// Debug() is to print trace useful for debugging purposes. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_DEBUG_2(msg) instead.
	inline void Debug2(const std::string& message,
					  const std::string& fileName,
					  const std::string& functionName,
					  int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "DEBUG_2: "
				<< message << "\n";  // bufferred output
	}

	// Debug() is to print trace useful for debugging purposes. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_DEBUG_3(msg) instead.
	inline void Debug3(const std::string& message,
					  const std::string& fileName,
					  const std::string& functionName,
					  int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "DEBUG_3: "
				<< message << "\n";  // bufferred output
	}

	// Debug() is to print trace useful for debugging purposes. NOT TO BE CALLED DIRECTLY FOR LOGGING. Call LOG_DEBUG_ALL(msg) instead.
	inline void DebugAll(const std::string& message,
					  const std::string& fileName,
					  const std::string& functionName,
					  int   lineNumber) {
 		*output << getTracePrefix(fileName, functionName, lineNumber) << "DEBUG_ALL: "
				<< message << "\n";  // bufferred output
	}

};

// global Logger& LOG. in this case getInstance() is called just once
extern Logger& LOG;

#endif
