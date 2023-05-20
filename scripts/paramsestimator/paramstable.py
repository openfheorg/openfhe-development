# # given a distribution type and a security level, you can get the maxQ for a
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

LogQ = { }

LogQks = { }


class paramsetvars:
    def __init__(self, n, q, N, logQ, Qks, B_g, B_ks, B_rk, sigma):
        self.n = n #n
        self.q = q #mod_q
        self.logQ = logQ  #mod_Q numberBits
        self.N = N  # cyclOrder/2
        self.Qks = Qks #Qks modKS
        self.B_g = B_g #gadgetBase
        self.B_ks = B_ks #baseKS
        self.B_rk = B_rk #baseRK
        self.sigma = sigma #sigma stddev


STD128Q_OPT_3_nQks1 = paramsetvars(600, 4096, 2048, 50, 2**15, 2**25, 2**5, 2**5, 3.19)
STD128Q_OPT_3 = paramsetvars(585, 4096, 2048, 50, 2**15, 2**25, 2**5, 2**5, 3.19)

#linear relation of log(modulus) and dimension as [a,b] for each standard security level - log(modulus) = a*dimension + b
paramlinear = {
    'STD128': [128, 0.026243550051145488, -0.19332645282074845],
    'STD128Q': [128, 0.024334365322949414, 0.026487788095649],
    'STD192': [192, 0.01843137255110034, -0.6666666695778614],
    'STD192Q': [192, 0.017254901960954656, -0.9019607843827292],
    'STD256': [256, 0.014352941174320843, -1.0014705882400903],
    'STD256Q': [256, 0.01339285714070515, -1.083333333337455]
}
'''
class performanceNumbers:
    def __init__(self, bootstrapKeySize, keyswitchKeySize, ciphertextSize, bootstrapKeygenTime, evalbingateTime):
    self.bootstrapKeySize = bootstrapKeySize
    self.keyswitchKeySize = keyswitchKeySize
    self.ciphertextSize = ciphertextSize
    self.bootstrapKeygenTime = bootstrapKeygenTime
    self.evalbingateTime = evalbingateTime


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
'''

#paramsetname: [securitylevel, dimension, modulussize, secret distribution]
'''
paramsDict = {
 'params128NQ1': [SecLev.HEStd_128_classic, 1024, 27, DistType.HEStd_ternary],
 'params192NQ1': [SecLev.HEStd_192_classic, 1024, 19, DistType.HEStd_ternary],
 'params256NQ1': [SecLev.HEStd_256_classic, 1024, 14, DistType.HEStd_ternary],
 'params128NQ2': [SecLev.HEStd_128_classic, 2048, 54, DistType.HEStd_ternary],
 'params192NQ2': [SecLev.HEStd_192_classic, 2048, 37, DistType.HEStd_ternary],
 'params256NQ2': [SecLev.HEStd_256_classic, 2048, 29, DistType.HEStd_ternary],
 'params128NQ3': [SecLev.HEStd_128_classic, 4096, 109, DistType.HEStd_ternary],
 'params192NQ3': [SecLev.HEStd_192_classic, 4096, 75, DistType.HEStd_ternary],
 'params256NQ3': [SecLev.HEStd_256_classic, 4096, 58, DistType.HEStd_ternary],
 'params128NQ4': [SecLev.HEStd_128_classic, 8192, 218, DistType.HEStd_ternary],
 'params192NQ4': [SecLev.HEStd_192_classic, 8192, 152, DistType.HEStd_ternary],
 'params256NQ4': [SecLev.HEStd_256_classic, 8192, 118, DistType.HEStd_ternary],
 'params128NQ5': [SecLev.HEStd_128_classic, 16384, 438, DistType.HEStd_ternary],
 'params192NQ5': [SecLev.HEStd_192_classic, 16384, 305, DistType.HEStd_ternary],
 'params256NQ5': [SecLev.HEStd_256_classic, 16384, 237, DistType.HEStd_ternary],
 'params128NQ6': [SecLev.HEStd_128_classic, 32768, 881, DistType.HEStd_ternary],
 'params192NQ6': [SecLev.HEStd_192_classic, 32768, 611, DistType.HEStd_ternary],
 'params256NQ6': [SecLev.HEStd_256_classic, 32768, 476, DistType.HEStd_ternary],

 'params128Nnks1': [SecLev.HEStd_128_classic, 512, 14, 15, 5, DistType.HEStd_ternary],
 'params192nQks1': [SecLev.HEStd_192_classic, 1024, 19, 15, 5, DistType.HEStd_ternary],
 'params256nQks1': [SecLev.HEStd_256_classic, 1024, 14, 6, 4, DistType.HEStd_ternary],

  'STD128Q_OPT_3_nQks1': [SecLev.HEStd_128_classic, 600, 15, 15, 5, DistType.HEStd_ternary],
}
'''
