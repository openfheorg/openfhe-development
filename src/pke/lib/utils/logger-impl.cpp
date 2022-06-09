#include "logger-impl.h"
#include <fstream>
#include "utils/exception.h"


Logger& LOG = Logger::getInstance();


void Logger::setLogFile(const std::string& fileName0)
{
	if( &std::cout != output )
		OPENFHE_THROW(lbcrypto::palisade_error, "Already opened [" + fileName0 + "] for output");

	fileName = fileName0;
	auto filePtr = new std::ofstream(fileName, std::ios::out|std::ios::trunc|std::ios::binary);
	if( !filePtr->good() )
	  OPENFHE_THROW(lbcrypto::palisade_error, "Error opening output file [" + fileName0 + "]");

	output = filePtr;
}

