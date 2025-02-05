#pragma once

#ifdef CRITICAL_SECTION
#include <mutex>
#define STD_CRITICAL_SECTION static std::mutex cs_mutex; std::lock_guard<std::mutex> cs_lock(cs_mutex);
#else
#define STD_CRITICAL_SECTION
#endif
