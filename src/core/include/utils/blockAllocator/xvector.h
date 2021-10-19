// @file TODO
//
// @copyright Copyright (c) TODO

// See
// http://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Performance-
// written by dcousins BBN

#ifndef _XVECTOR_H
#define _XVECTOR_H

#include <vector>
#include "stl_allocator.h"

template <class _Ty, class _Ax = stl_allocator<_Ty> >
class xvector : public std::vector<_Ty, _Ax> {};

#endif
