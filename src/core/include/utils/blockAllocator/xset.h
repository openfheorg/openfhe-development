// @file TODO
//
// @copyright Copyright (c) TODO

#ifndef _XSET_H
#define _XSET_H

#include <functional>
#include <set>
#include "stl_allocator.h"

template <class _Kty, class _Pr = std::less<_Kty>,
          class _Alloc = stl_allocator<_Kty> >
class xset : public std::set<_Kty, _Pr, _Alloc> {};

/// @see xset
template <class _Kty, class _Pr = std::less<_Kty>,
          class _Alloc = stl_allocator<_Kty> >
class xmultiset : public std::multiset<_Kty, _Pr, _Alloc> {};

#endif
