#!/usr/bin/python

'''Approach for generating standard security tables for fhe
1) Pick security distribution
2) Pick security level
3) Set number of threads for the lattice-estimator
4) (optional) specific lattice dimension
'''

import paramstable as stdparams
import binfhe_params_helper as helperfncs
from math import log2, floor, sqrt, ceil

def parameter_selector():
    print("Generate standard parameter tables for different security levels")

    #bootstrapping technique
    secret_dist = int(input("Enter secret key distribution (0 = uniform, 1 = error, 2 = ternary): "))
    helperfncs.test_range(secret_dist, 0, 2)

    exp_sec_level = input("Enter Security level (STD128, STD128Q, STD192, STD192Q, STD256, STD256Q): ")

    ring_dim = int(input("Enter ring dimension: "))

    num_threads = int(input("Enter number of threads that can be used to run the lattice-estimator: "))

    #processing parameters based on the inputs
    if (exp_sec_level[-1] == "Q"):
        is_quantum = True
    else:
        is_quantum = False

    #check if ring_dim is a power of 2
    if ring_dim <= 0:
        is_dim_pow2 = False
    else:
        is_dim_pow2 = (ring_dim & (ring_dim - 1) == 0)

    secret_dist_des = ""
    if secret_dist == 0:
        secret_dist_des = "uniform"
    elif secret_dist == 1:
        secret_dist_des = "error"
    elif secret_dist == 2:
        secret_dist_des = "ternary"

    #set ptmod based on num of inputs
    dimlist = []
    modlist = []
    if (ring_dim == 0):
        for i in [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]:
            dim, mod = generate_dim_mod(exp_sec_level, i, secret_dist_des, num_threads, True, is_quantum)
    else:
        dim, mod = generate_dim_mod(exp_sec_level, ring_dim, secret_dist_des, num_threads, is_dim_pow2, is_quantum)

    if ((dim == 0) or (mod == 0)):
        print("initial lattice dimension too small to run the estimator for this security level, increasing initial value")
    else:
        print("Dimension N: ", dim)
        print("Modulus Q bits: ", log2(mod))

def generate_dim_mod(exp_sec_level, ringdim, secret_dist, num_threads, is_dim_pow2, is_quantum):
    logmod = helperfncs.get_mod(ringdim, exp_sec_level) #find analytical estimate for starting point of Qks

    #check security by running the estimator and adjust modulus if needed
    dim, mod = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], ringdim, 2**logmod, secret_dist, num_threads, False, True, is_dim_pow2, is_quantum)

    return dim, mod
parameter_selector()
