# Block Allocator

## Motivation

We create stl-compatible custom block allocators for various types which allows for fast allocation and free-ing.

**Note**: the `xY.h` is such that the `x` describes that we are using the custom allocator class, and the `Y` describes the underlying type e.g: `list` or `map`, etc.

## References

For more context, read:

1) [An Efficient C++ Fixed Block Memory Allocator]( http://www.codeproject.com/Articles/1083210/An-efficient-Cplusplus-fixed-block-memory-allocato)

TL;DR global heap allocation can be slow and nondeterministic. Also, this eliminates the possibility of memory allocation fault caused by a fragmented heap.

2) [Replace malloc/free with a Fast Fixed Block Memory Allocator](https://www.codeproject.com/Articles/1084801/Replace-malloc-free-with-a-fast-fixed-block-memory)

TL;DR replaces `malloc` and `free` with `xmalloc` and `xfree` which take advantage of the `Allocator` from above

3) [A Custom STL std::allocator Replacement Improves Performance](https://www.codeproject.com/Articles/1089905/A-Custom-STL-std-allocator-Replacement-Improves-Pe)

TL;DR describes how to create a STL-compatible version of the above code.