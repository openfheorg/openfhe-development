OpenFHE Library - Interactive Bootstrapping
=====================================================================================================

OpenFHE provides two methods for interactive CKKS bootstrapping:
* The $n$-party method described in Appendix E of https://eprint.iacr.org/2023/1203. This method is an optimized version of the method originally proposed in https://eprint.iacr.org/2020/304 and https://arxiv.org/abs/2009.00349.
* The 2-party method proposed in Appendix D of https://eprint.iacr.org/2023/1203, which is based on the idea of distributed rounding.

The 2-party method is more efficient than the $n$-party method for the case when $n=2$.
