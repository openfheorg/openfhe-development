// @file TODO
//
// @copyright Copyright (c) TODO

#ifndef _XQUEUE_H
#define _XQUEUE_H

#include <list>
#include <queue>
#include "stl_allocator.h"

template <class _Tp, class _Sequence = std::list<_Tp, stl_allocator<_Tp> > >
class xqueue : public std::queue<_Tp, _Sequence> {};

#endif
