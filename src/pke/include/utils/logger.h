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
