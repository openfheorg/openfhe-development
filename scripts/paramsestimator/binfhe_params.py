#!/usr/bin/python

'''Approach for determining parameters for binfhe
1)	Pick security level
2)	Set expected decryption failure rate
3)	Specify max number of inputs to a boolean gate
Measure enc/rec/dec time, and throughput ( #bits in (3+/these times) and document.
'''

import paramstable as stdparams
import binfhe_params_helper as helperfncs
import math

def parameter_selector():
    print("Parameter selectorfor FHEW like schemes")

    #bootstrapping technique
    dist_type = int(input("Enter Distribution (0 = HEStd_uniform, 1 = HEStd_error, 2 = HEStd_ternary): "))
    helperfncs.test_range(dist_type, 0, 2)

    exp_sec_level = int(input("Enter Security level (0 = 128, 1 = 192, 2 = 256): "))
    helperfncs.test_range(sec_level, 0, 2)

    is_quantum = int(input("Include quantum attack estimates for security? (0 = False, 1 = True): "))
    helperfncs.test_range(is_quantum, 0, 1)

    exp_decryption_failure = int(input("Enter expected decryption failure rate (as a power of 2, for example, enter -32 for 2^-32 failure rate): "))

    num_of_inputs = int(input("Enter expected number of inputs to the boolean gate: "))

    #set ptmod based on num of inputs
    ptmod = 2*num_of_inputs

    #Set ringsize n, Qks, N, Q based on the security level
    ringsize_n = 1024
    ringsize_N = 2048

        modulus_q = N
        modulus_Qks = analytical_estimate(n) #find analytical estimate for starting point of Qks
        modulus_Q = analytical_estimate(N)

        #create paramset object
        param_set_opt = paramsetvars("paramsetopt", modulus_Q, ringsize_N, ringsize_n, modulus_q, modulus_Qks, B_g, B_ks)
    get_noise_from_cpp_code(param_set_opt)
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)

    #increase ctmod q to 2N and everything else constant

    #optimize n, Qks to reduce the noise

    #increase ringsize_N if ringsize_n had to be increased to larger than current value of ringsize_N -- to be done within the optimizing function


    #optimize B_g, B_ks to reduce the noise


    print("final parameters")
    print("dist_type: ",dist_type)
    print("sec_level: ", sec_level)
    print("decryption failure rate: ", ringsize)
