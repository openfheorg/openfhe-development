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

    exp_sec_level = input("Enter Security level (STD128, STD128Q, STD192, STD192Q, STD256, STD256Q): ")

    #is_quantum = int(input("Include quantum attack estimates for security? (0 = False, 1 = True): "))
    #helperfncs.test_range(is_quantum, 0, 1)

    exp_decryption_failure = int(input("Enter expected decryption failure rate (as a power of 2, for example, enter -32 for 2^-32 failure rate): "))

    num_of_inputs = int(input("Enter expected number of inputs to the boolean gate: "))

    num_of_samples = int(input("Enter expected number of samples to estimate noise: "))

    #processing parameters based on the inputs
    if (exp_sec_level[-1] == "Q"):
        is_quantum = True
    else:
        is_quantum = False

    #set ptmod based on num of inputs
    ptmod = 2*num_of_inputs

    for d_g in [2, 3, 4]:
        #Set ringsize n, Qks, N, Q based on the security level
        ringsize_N = [1024, 2048]

        #other variables
        lattice_n = 500 #start with this value and binary search on n to find optimal parameter set

        #compute target noise level for the expected decryption failure rate
        target_noise_level = get_target_noise(exp_decryption_failure, ptmod, modulus_q, num_of_inputs)

        modulus_q = 2*ringsize_N #later optimize for either q = N or q = 2N
        modulus_Qks = get_mod(lattice_n, exp_sec_level) #find analytical estimate for starting point of Qks
        modulus_Q = get_mod(ringsize_N, exp_sec_level) #later add code to verify that this Q is optimal with estimator

        #create paramset object
        param_set_opt = paramsetvars("paramsetopt", modulus_Q, ringsize_N, ringsize_n, modulus_q, modulus_Qks, B_g, B_ks)

        actual_noise = get_noise_from_cpp_code(param_set_opt, num_of_samples)##########################################################run script CPP###########

        #if (actual_noise > target_noise_level):
        #    param_set_opt.q = 2*ringsize_N
        #    actual_noise = get_noise_from_cpp_code(param_set_opt, num_of_samples)##########################################################run script CPP###########
        for ringsize_N in [1024, 2048]:
        if (actual_noise > target_noise_level):
            opt_n = optimize_noise(actual_noise, target_noise_level, param_set_opt)#lattice_n, ringsize_N)
            param_set_opt.N =
            if (opt_n == 0):
                opt_n = optimize_noise(actual_noise, target_noise_level, lattice_n, ringsize_N)

        #increase ctmod q to 2N and everything else constant

        #optimize n, Qks to reduce the noise

        #increase ringsize_N if ringsize_n had to be increased to larger than current value of ringsize_N -- to be done within the optimizing function


    print("final parameters")
    print("dist_type: ",dist_type)
    print("sec_level: ", sec_level)
    print("decryption failure rate: ", ringsize)

def get_mod(dim, exp_sec_level):
    #get linear relation coefficients for log(modulus) and dimension for the input security level
    a = stdparams.paramlinDict[exp_sec_level][0]
    b = stdparams.paramlinDict[exp_sec_level][1]

    mod = ceil(a*dim + b) #find analytical estimate for starting point of Qks
    return mod

def optimize_noise(curr_noise, target_noise_level, start_n, end_N):
    ringsize_N = end_N
    found = False
    n = 0
    while(start_n < end_N):
        new_n = (start_n + end_N)/2
        mod_Qks = get_mod(new_n, exp_sec_level)
        new_noise = get_noise(params)
        if (new_noise > target_noise_level and prev_noise <= target_noise_level):
            found = True
            n = prev_n
            break
        if (new_noise < curr_noise):
            min_noise = new_noise
            end_N = new_n - 1
        else:
            start_n = new_n + 1
        prev_noise = new_noise
        prev_n = new_n

    return n
