# @file stdlatticeparms.h: Header for the standard values for Lattice Parms, as
# determined by homomorphicencryption.org
# @author TPOC: contact@palisade-crypto.org

# this is the representation of the standard lattice parameters defined in the
# Homomorphic Encryption Standard, as defined by
# http://homomorphicencryption.org

# given a distribution type and a security level, you can get the maxQ for a
# given ring dimension, and you can get the ring dimension given a maxQ

# The code below is very specific to the layout of the DistributionType and
# SecurityLevel enums IF you change them, go look at and change byRing and
# byLogQ

from enum import Enum

class DistType(Enum):
    HEStd_uniform = 0
    HEStd_error = 1
    HEStd_ternary = 2


class SecLev(Enum):
    HEStd_128_classic = 0
    HEStd_192_classic = 1
    HEStd_256_classic = 2
    HEStd_NotSet = 3

class Paramset(Enum):
    params128NQ1 = 0
    params128NQ2 = 1
    params128NQ3 = 2
    params128NQ4 = 3
    params128NQ5 = 4
    params128NQ6 = 5
    params192NQ1 = 6
    params192NQ2 = 7
    params192NQ3 = 8
    params192NQ4 = 9
    params192NQ5 = 10
    params192NQ6 = 11
    params256NQ1 = 12
    params256NQ2 = 13
    params256NQ3 = 14
    params256NQ4 = 15
    params256NQ5 = 16
    params256NQ6 = 17
    params128nQks1 = 18
    params192nQks2 = 19
    params256nQks3 = 20
    
LogQ = { }

LogQks = { }
'''
LogQ[(DistType.HEStd_uniform, 1024, SecLev.HEStd_128_classic)] = 29
LogQ[(DistType.HEStd_uniform, 1024, SecLev.HEStd_192_classic)] = 21
LogQ[(DistType.HEStd_uniform, 1024, SecLev.HEStd_256_classic)] = 16
LogQ[(DistType.HEStd_uniform, 2048, SecLev.HEStd_128_classic)] = 56
LogQ[(DistType.HEStd_uniform, 2048, SecLev.HEStd_192_classic)] = 39
LogQ[(DistType.HEStd_uniform, 2048, SecLev.HEStd_256_classic)] = 31
LogQ[(DistType.HEStd_uniform, 4096, SecLev.HEStd_128_classic)] = 111
LogQ[(DistType.HEStd_uniform, 4096, SecLev.HEStd_192_classic)] = 77
LogQ[(DistType.HEStd_uniform, 4096, SecLev.HEStd_256_classic)] = 60
LogQ[(DistType.HEStd_uniform, 8192, SecLev.HEStd_128_classic)] = 220
LogQ[(DistType.HEStd_uniform, 8192, SecLev.HEStd_192_classic)] = 154
LogQ[(DistType.HEStd_uniform, 8192, SecLev.HEStd_256_classic)] = 120
LogQ[(DistType.HEStd_uniform, 16384, SecLev.HEStd_128_classic)] = 440
LogQ[(DistType.HEStd_uniform, 16384, SecLev.HEStd_192_classic)] = 307
LogQ[(DistType.HEStd_uniform, 16384, SecLev.HEStd_256_classic)] = 239
LogQ[(DistType.HEStd_uniform, 32768, SecLev.HEStd_128_classic)] = 880
LogQ[(DistType.HEStd_uniform, 32768, SecLev.HEStd_192_classic)] = 612
LogQ[(DistType.HEStd_uniform, 32768, SecLev.HEStd_256_classic)] = 478

LogQ[(DistType.HEStd_error, 1024, SecLev.HEStd_128_classic)] = 29
LogQ[(DistType.HEStd_error, 1024, SecLev.HEStd_192_classic)] = 21
LogQ[(DistType.HEStd_error, 1024, SecLev.HEStd_256_classic)] = 16
LogQ[(DistType.HEStd_error, 2048, SecLev.HEStd_128_classic)] = 56
LogQ[(DistType.HEStd_error, 2048, SecLev.HEStd_192_classic)] = 39
LogQ[(DistType.HEStd_error, 2048, SecLev.HEStd_256_classic)] = 31
LogQ[(DistType.HEStd_error, 4096, SecLev.HEStd_128_classic)] = 111
LogQ[(DistType.HEStd_error, 4096, SecLev.HEStd_192_classic)] = 77
LogQ[(DistType.HEStd_error, 4096, SecLev.HEStd_256_classic)] = 60
LogQ[(DistType.HEStd_error, 8192, SecLev.HEStd_128_classic)] = 220
LogQ[(DistType.HEStd_error, 8192, SecLev.HEStd_192_classic)] = 154
LogQ[(DistType.HEStd_error, 8192, SecLev.HEStd_256_classic)] = 120
LogQ[(DistType.HEStd_error, 16384, SecLev.HEStd_128_classic)] = 440
LogQ[(DistType.HEStd_error, 16384, SecLev.HEStd_192_classic)] = 307
LogQ[(DistType.HEStd_error, 16384, SecLev.HEStd_256_classic)] = 239
LogQ[(DistType.HEStd_error, 32768, SecLev.HEStd_128_classic)] = 883
LogQ[(DistType.HEStd_error, 32768, SecLev.HEStd_192_classic)] = 613
LogQ[(DistType.HEStd_error, 32768, SecLev.HEStd_256_classic)] = 478
'''
LogQ[(Paramset.params128NQ1, DistType.HEStd_ternary, 1024, SecLev.HEStd_128_classic)] = 27
LogQ[(Paramset.params192NQ1, DistType.HEStd_ternary, 1024, SecLev.HEStd_192_classic)] = 19
LogQ[(Paramset.params256NQ1, DistType.HEStd_ternary, 1024, SecLev.HEStd_256_classic)] = 14
LogQ[(Paramset.params128NQ2, DistType.HEStd_ternary, 2048, SecLev.HEStd_128_classic)] = 54
LogQ[(Paramset.params192NQ2, DistType.HEStd_ternary, 2048, SecLev.HEStd_192_classic)] = 37
LogQ[(Paramset.params256NQ2,DistType.HEStd_ternary, 2048, SecLev.HEStd_256_classic)] = 29
LogQ[(Paramset.params128NQ3,DistType.HEStd_ternary, 4096, SecLev.HEStd_128_classic)] = 109
LogQ[(Paramset.params192NQ3,DistType.HEStd_ternary, 4096, SecLev.HEStd_192_classic)] = 75
LogQ[(Paramset.params256NQ3,DistType.HEStd_ternary, 4096, SecLev.HEStd_256_classic)] = 58
LogQ[(Paramset.params128NQ4,DistType.HEStd_ternary, 8192, SecLev.HEStd_128_classic)] = 218
LogQ[(Paramset.params192NQ4,DistType.HEStd_ternary, 8192, SecLev.HEStd_192_classic)] = 152
LogQ[(Paramset.params256NQ4,DistType.HEStd_ternary, 8192, SecLev.HEStd_256_classic)] = 118
LogQ[(Paramset.params128NQ5,DistType.HEStd_ternary, 16384, SecLev.HEStd_128_classic)] = 438
LogQ[(Paramset.params192NQ5,DistType.HEStd_ternary, 16384, SecLev.HEStd_192_classic)] = 305
LogQ[(Paramset.params256NQ5,DistType.HEStd_ternary, 16384, SecLev.HEStd_256_classic)] = 237
LogQ[(Paramset.params128NQ6,DistType.HEStd_ternary, 32768, SecLev.HEStd_128_classic)] = 881
LogQ[(Paramset.params192NQ6,DistType.HEStd_ternary, 32768, SecLev.HEStd_192_classic)] = 611
LogQ[(Paramset.params256NQ6,DistType.HEStd_ternary, 32768, SecLev.HEStd_256_classic)] = 476

LogQks[(Paramset.params128Nnks1, DistType.HEStd_ternary, 512, SecLev.HEStd_128_classic)] = 14
LogQks[(Paramset.params192nQks1, DistType.HEStd_ternary, 1024, SecLev.HEStd_192_classic)] = 19
LogQks[(Paramset.params256nQks1, DistType.HEStd_ternary, 1024, SecLev.HEStd_256_classic)] = 14
'''
params128NQ1 = LWE.Parameters(n=1024, q=2^27, Xs=ND.SparseTernary(1024, 341, 341), Xe=ND.DiscreteGaussian(3.19))
params128NQ2 = LWE.Parameters(n=2048, q=2^54, Xs=ND.SparseTernary(2048, 682, 682), Xe=ND.DiscreteGaussian(3.19))
params128NQ3 = LWE.Parameters(n=4096, q=2^109, Xs=ND.SparseTernary(4096, 1364, 1364), Xe=ND.DiscreteGaussian(3.19))
params128NQ4 = LWE.Parameters(n=8192, q=2^218, Xs=ND.SparseTernary(8192, 2728, 2728), Xe=ND.DiscreteGaussian(3.19))
params128NQ5 = LWE.Parameters(n=16384, q=2^438, Xs=ND.SparseTernary(16384, 5456, 5456), Xe=ND.DiscreteGaussian(3.19))
params128NQ6 = LWE.Parameters(n=32768, q=2^881, Xs=ND.SparseTernary(32768, 10912, 10912), Xe=ND.DiscreteGaussian(3.19))
params192NQ1 = LWE.Parameters(n=1024, q=2^19, Xs=ND.SparseTernary(1024, 341, 341), Xe=ND.DiscreteGaussian(3.19))
params192NQ2 = LWE.Parameters(n=2048, q=2^37, Xs=ND.SparseTernary(2048, 682, 682), Xe=ND.DiscreteGaussian(3.19))
params192NQ3 = LWE.Parameters(n=4096, q=2^75, Xs=ND.SparseTernary(4096, 1364, 1364), Xe=ND.DiscreteGaussian(3.19))
params192NQ4 = LWE.Parameters(n=8192, q=2^152, Xs=ND.SparseTernary(8192, 2728, 2728), Xe=ND.DiscreteGaussian(3.19))
params192NQ5 = LWE.Parameters(n=16384, q=2^305, Xs=ND.SparseTernary(16384, 5456, 5456), Xe=ND.DiscreteGaussian(3.19))
params192NQ6 = LWE.Parameters(n=32768, q=2^611, Xs=ND.SparseTernary(32768, 10912, 10912), Xe=ND.DiscreteGaussian(3.19))
params256NQ1 = LWE.Parameters(n=1024, q=2^14, Xs=ND.SparseTernary(1024, 341, 341), Xe=ND.DiscreteGaussian(3.19))
params256NQ2 = LWE.Parameters(n=2048, q=2^29, Xs=ND.SparseTernary(2048, 682, 682), Xe=ND.DiscreteGaussian(3.19))
params256NQ3 = LWE.Parameters(n=4096, q=2^58, Xs=ND.SparseTernary(4096, 1364, 1364), Xe=ND.DiscreteGaussian(3.19))
params256NQ4 = LWE.Parameters(n=8192, q=2^118, Xs=ND.SparseTernary(8192, 2728, 2728), Xe=ND.DiscreteGaussian(3.19))
params256NQ5 = LWE.Parameters(n=16384, q=2^237, Xs=ND.SparseTernary(16384, 5456, 5456), Xe=ND.DiscreteGaussian(3.19))
params256NQ6 = LWE.Parameters(n=32768, q=2^476, Xs=ND.SparseTernary(32768, 10912, 10912), Xe=ND.DiscreteGaussian(3.19))

params128nQks1 = LWE.Parameters(n=512, q=2^14, Xs=ND.SparseTernary(512, 171, 171), Xe=ND.DiscreteGaussian(3.19))
params192nQks1 = LWE.Parameters(n=1024, q=2^19, Xs=ND.SparseTernary(1024, 381, 381), Xe=ND.DiscreteGaussian(3.19))
params256nQks1 = LWE.Parameters(n=1024, q=2^14, Xs=ND.SparseTernary(1024, 381, 381), Xe=ND.DiscreteGaussian(3.19))
'''
