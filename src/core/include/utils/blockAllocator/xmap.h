// @file TODO
//
// @copyright Copyright (c) TODO

#ifndef _XMAP_H
#define _XMAP_H

#include <functional>
#include <map>
#include <utility>

#include "stl_allocator.h"

template <class _Kty, class _Ty, class _Pr = std::less<_Kty>,
          class _Alloc = stl_allocator<std::pair<const _Kty, _Ty> > >
class xmap : public std::map<_Kty, _Ty, _Pr, _Alloc> {};

template <class _Kty, class _Ty, class _Pr = std::less<_Kty>,
          class _Alloc = stl_allocator<std::pair<const _Kty, _Ty> > >
class xmultimap : public std::multimap<_Kty, _Ty, _Pr, _Alloc> {};

#endif
