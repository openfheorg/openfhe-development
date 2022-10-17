10/17/2022: OpenFHE 0.9.5 (development) is released

* Improves precision of CKKS bootstrapping
* Fixes a building error in MacOS
* Includes other small bug fixes

10/05/2022: OpenFHE 0.9.4 (development) is released

* Fixes build errors for NATIVE_SIZE=32
* Includes other small bug fixes

09/16/2022: OpenFHE 0.9.3 (development) is released

* Fixes build errors in MinGW
* Fixes a compilation error with g++ 12
* Includes fixes for the Proxy Re-Encryption functionality

08/18/2022: OpenFHE 0.9.2 (development) is released

* Fixes a compilation error for some versions of MacOS
* Fixes a problem with docker configuration
* Includes bug fixes from PALISADE v1.11.7
* Adds support for RISC-V architecture
* Small optimizations for some of the CKKS operations

07/21/2022: OpenFHE 0.9.1 (development) is released

* Fixes a compilation error for NATIVE_SIZE=128 in MacOS
* Fixes small bugs

07/19/2022: OpenFHE 0.9.0 (development) is released

Includes all prior FHE functionality of PALISADE. Also adds the following new features:
* New BGV and BFV RNS variants proposed in https://eprint.iacr.org/2021/204
* A new CKKS RNS variant variant proposed in https://eprint.iacr.org/2020/1118
* A full RNS implementation of CKKS bootstrapping
* Adds support for multiple hardware acceleration backends using a Hardware Abstraction Layer feature
* Large-precision comparison and other algorithms proposed in https://eprint.iacr.org/2021/1337

**Note**: OpenFHE stems off of PALISADE. Refer to the following for [PALISADE release notes](https://gitlab.com/palisade/palisade-development/-/blob/master/Release_Notes.md)
