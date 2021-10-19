// @file TODO
//
// @copyright Copyright (c) TODO

#ifndef _XSSTREAM_H
#define _XSSTREAM_H

#include <sstream>
#include <string>

#include "stl_allocator.h"

typedef std::basic_stringstream<char, std::char_traits<char>,
                                stl_allocator<char>>
    xstringstream;
typedef std::basic_ostringstream<char, std::char_traits<char>,
                                 stl_allocator<char>>
    xostringstream;

typedef std::basic_stringstream<wchar_t, std::char_traits<wchar_t>,
                                stl_allocator<wchar_t>>
    xwstringstream;
typedef std::basic_ostringstream<wchar_t, std::char_traits<wchar_t>,
                                 stl_allocator<wchar_t>>
    xwostringstream;

#endif
