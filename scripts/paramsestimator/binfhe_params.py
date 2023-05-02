#!/usr/bin/python

'''Approach for determining parameters for binfhe
1)	Pick security level
2)	Set expected decryption failure rate
3)	Specify max number of inputs to a boolean gate
Measure enc/rec/dec time, and throughput ( #bits in (3+/these times) and document.
'''

import paramstable as stdparams
import binfhe_params_helper as helperfncs
from math import log2, floor, sqrt, ceil

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

    d_ks = int(input("Enter key switching digit size: "))

    #processing parameters based on the inputs
    if (exp_sec_level[-1] == "Q"):
        is_quantum = True
    else:
        is_quantum = False

    #set ptmod based on num of inputs
    ptmod = 2*num_of_inputs

    B_rk = 32
    sigma = 3.19

    for d_g in [2, 3, 4]:
        #Set ringsize n, Qks, N, Q based on the security level
        print("d_g loop: ", d_g)
        ringsize_N = 1024
        while (ringsize_N <= 2048):

            #other variables
            lattice_n = ringsize_N/2 #start with this value and binary search on n to find optimal parameter set

            modulus_q = 2*ringsize_N #later optimize for either q = N or q = 2N
            logmodQks = get_mod(lattice_n, exp_sec_level) #find analytical estimate for starting point of Qks
            modulus_Qks = 2**logmodQks
            logmodQ = get_mod(ringsize_N, exp_sec_level) #later add code to verify that this Q is optimal with estimator
            #todo - add another flag for nativeopt 32 depending on whether logQ <=32 or not
            B_g = 2**floor(logmodQ/d_g)
            B_ks = 2**floor(logmodQks/d_ks) #later - optimize for d_ks

            #create paramset object
            param_set_opt = stdparams.paramsetvars(lattice_n, modulus_q, ringsize_N, logmodQ, modulus_Qks, B_g, B_ks, B_rk, sigma)

            #optimize n, Qks to reduce the noise
            #compute target noise level for the expected decryption failure rate
            target_noise_level = helperfncs.get_target_noise(exp_decryption_failure, ptmod, modulus_q, num_of_inputs)
            print("target noise: ", target_noise_level)

            actual_noise = helperfncs.get_noise_from_cpp_code(param_set_opt, num_of_samples//8)##########################################################run script CPP###########

            #if (actual_noise > target_noise_level):
            #    param_set_opt.q = 2*ringsize_N
            #    actual_noise = get_noise_from_cpp_code(param_set_opt, num_of_samples)##########################################################run script CPP###########
            opt_n = 0

            if (actual_noise > target_noise_level):
                print("here in if actual greater than target noise")
                opt_n, optlogmodQks = binary_search_n(lattice_n, ringsize_N, actual_noise, exp_sec_level, target_noise_level, num_of_samples//8, param_set_opt)#lattice_n, ringsize_N)

            if (opt_n != 0):
                break
            else:
                ringsize_N = ringsize_N*2

        if (opt_n == 0):
            print("cannot find parameters")
        else:
            #increase ctmod q to 2N and everything else constant - later
            optQks = 2**optlogmodQks
            B_g = floor(logmodQ/d_g)
            B_ks = floor(logmodQks/3)

            print("final parameters")
            print("Input parameters: ")
            print("dist_type: ",dist_type)
            print("sec_level: ", exp_sec_level)
            print("decryption failure rate: ", exp_decryption_failure)
            print("num_of_inputs: ", num_of_inputs)
            print("num_of_samples: ", num_of_samples)
            print("Output parameters: ")
            print("lattice dimension n: ", opt_n)
            print("ringsize N: ", ringsize_N)
            print("lattice modulus: ", modulus_q)
            print("size of ring modulus Q: ", logmodQ)
            print("optimal key switching modulus  Qks: ", optQks)
            print("gadget digit base B_g: ", B_g)
            print("gadget digit base B_ks: ", B_ks)

def get_mod(dim, exp_sec_level):
    #get linear relation coefficients for log(modulus) and dimension for the input security level
    a = stdparams.paramlinear[exp_sec_level][0]
    b = stdparams.paramlinear[exp_sec_level][1]

    mod = ceil(a*dim + b) #find analytical estimate for starting point of Qks
    return mod

def optimize_noise(curr_noise, target_noise_level, params):
    start_n = params.n
    end_N = params.N


    return n

def binary_search_n(start_n, end_N, prev_noise, exp_sec_level, target_noise_level, num_of_samples, params):
    n = 0

    while(start_n <= end_N):
        new_n = (start_n + end_N)/2
        print("new n: ", new_n)

        logmodQks = get_mod(new_n, exp_sec_level)
        params.n = new_n
        params.Qks = 2**logmodQks
        B_ks = floor(logmodQks/3) #assuming d_ks = 2
        params.B_ks = B_ks
        new_noise = helperfncs.get_noise_from_cpp_code(params, num_of_samples)
        if (new_noise > target_noise_level and prev_noise <= target_noise_level):
            found = True
            n = prev_n
            break
        if (new_noise < prev_noise):
            min_noise = new_noise
            end_N = new_n - 1
        else:
            start_n = new_n + 1
        prev_noise = new_noise
        start_n = new_n

        return n, logmodQks

parameter_selector()
