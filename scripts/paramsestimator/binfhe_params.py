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

    exp_decryption_failure = int(input("Enter expected decryption failure rate (for example, enter -32 for 2^-32 failure rate): "))

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
        opt_n = 0
        while (ringsize_N <= 2048):
            modulus_q = ringsize_N #later optimize for either q = N or q = 2N
            while (modulus_q <= 2*ringsize_N):
                #other variables
                lattice_n = 500 # for stdnum security, could set to ringsize_N/2 #start with this value and binary search on n to find optimal parameter set

                logmodQksu = get_mod(lattice_n, exp_sec_level) #find analytical estimate for starting point of Qks
                logmodQu = get_mod(ringsize_N, exp_sec_level) #later add code to verify that this Q is optimal with estimator

                #check security by running the estimator and adjust modulus if needed
                dimn, modulus_Qks = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], lattice_n, 2**logmodQksu, False, True, False, is_quantum)
                dimN, modulus_Q = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], ringsize_N, 2**logmodQu, False, True, False, is_quantum)

                print("dimn, modulus_Qks first: ******* ", dimn, modulus_Qks)
                if (dimn > dimN):
                    print("estimator adjusted the dimension")
                    break
                elif ((dimn == 0) or (modulus_Qks == 0)):
                    print("initial lattice dimension too small to run the estimator for this security level, increasing initial value")

                while ((dimn == 0) and (modulus_Qks == 0)):
                    lattice_n = lattice_n + 100
                    logmodQksu = get_mod(lattice_n, exp_sec_level)
                    print("***********lattice_n*********", lattice_n)
                    print("***********logmodQksu*********", logmodQksu)
                    dimn, modulus_Qks = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], lattice_n, 2**logmodQksu, False, True, False, is_quantum)

                #check again
                if ((dimn > dimN) or (dimn == 0) or (modulus_Qks == 0)):
                    print("starting lattice dimension is 0 or greater than large N")
                    break

                print("***********lattice_n after while*********", lattice_n)
                print("***********modulus_Qks after while*********", modulus_Qks)
                #modulus_Qks = 2**logmodQks
                logmodQks = log2(modulus_Qks)
                logmodQ = log2(modulus_Q)

                while (logmodQ < 14):
                    modulus_Q = modulus_Q*2
                    logmodQ = log2(modulus_Q)

                if (logmodQks >= 32):
                    logmodQks = 30

                #todo - add another flag for nativeopt 32 depending on whether logQ <=32 or not
                B_g = 2**floor(logmodQ/d_g)
                B_ks = 2**floor(logmodQks/d_ks) #later - optimize for d_ks

                while (B_ks >= 256):# or ()32gb limit on complexity:
                    B_ks = B_ks/2
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

                if (actual_noise > target_noise_level):
                    print("here in if actual greater than target noise")
                    opt_n, optlogmodQks, optB_ks = binary_search_n(lattice_n, ringsize_N, actual_noise, exp_sec_level, target_noise_level, num_of_samples//8, d_ks, param_set_opt)#lattice_n, ringsize_N)
                    print("opt_n after binary search: ", opt_n)
                else:
                    opt_n = lattice_n

                if (opt_n != 0):
                    break
                else:
                    modulus_q = modulus_q*2

            if (opt_n != 0):
                break
            else:
                ringsize_N = ringsize_N*2

        if (opt_n == 0):
            print("cannot find parameters for d_g: ", d_g)
        else:
            #increase ctmod q to 2N and everything else constant - later
            optQks = 2**optlogmodQks
            B_g = 2**floor(logmodQ/d_g)

            param_set_final = stdparams.paramsetvars(opt_n, modulus_q, ringsize_N, logmodQ, optQks, B_g, optB_ks, B_rk, sigma)
            finalnoise = helperfncs.get_noise_from_cpp_code(param_set_final, 1000)##########################################################run script CPP###########
            final_dec_fail_rate = helperfncs.get_decryption_failure(finalnoise, ptmod, modulus_q, num_of_inputs)

            print("final parameters")
            print("Input parameters: ")
            print("dist_type: ",dist_type)
            print("sec_level: ", exp_sec_level)
            print("expected decryption failure rate: ", exp_decryption_failure)
            print("actual decryption failure rate: ", final_dec_fail_rate)
            print("num_of_inputs: ", num_of_inputs)
            print("num_of_samples: ", num_of_samples)
            print("Output parameters: ")
            print("lattice dimension n: ", opt_n)
            print("ringsize N: ", ringsize_N)
            print("lattice modulus: ", modulus_q)
            print("size of ring modulus Q: ", logmodQ)
            print("optimal key switching modulus  Qks: ", optQks)
            print("gadget digit base B_g: ", B_g)
            print("key switching digit base B_ks: ", optB_ks)

def get_mod(dim, exp_sec_level):
    #get linear relation coefficients for log(modulus) and dimension for the input security level
    a = stdparams.paramlinear[exp_sec_level][1]
    b = stdparams.paramlinear[exp_sec_level][2]

    mod = ceil(a*dim + b) #find analytical estimate for starting point of Qks
    return mod

#def optimize_noise(curr_noise, target_noise_level, params):
#    start_n = params.n
#    end_N = params.N

#    return n

#add d_ks to the function
def binary_search_n(start_n, end_N, prev_noise, exp_sec_level, target_noise_level, num_of_samples, d_ks, params):
    n = 0

    retlogmodQks = 0
    retBks = 0
    while(start_n <= end_N):
        new_n = floor((start_n + end_N)/2)
        print("new n: ", new_n)

        logmodQks = get_mod(new_n, exp_sec_level)
        if (logmodQks >= 32):
            logmodQks = 30

        params.n = new_n
        params.Qks = 2**logmodQks
        B_ks = 2**floor(logmodQks/d_ks)
        while (B_ks >= 256):
            B_ks = B_ks/2

        params.B_ks = B_ks
        print("B_ks in function: ", B_ks)
        print("d_ks in function: ", d_ks)
        new_noise = helperfncs.get_noise_from_cpp_code(params, num_of_samples)
        #if (new_noise < target_noise_level):
        #    found = True
        #    n = new_n
        #    break
        #if (new_noise >= prev_noise):
        #    min_noise = new_noise
        #    end_N = new_n - 1
        #else:
        #    start_n = new_n + 1

        if (new_noise > target_noise_level and prev_noise <= target_noise_level):
            found = True
            n = prev_n
            retlogmodQks = prevlogmodQks
            retBks = prevBks
            break
        if (new_noise < target_noise_level):
            n = new_n
            retlogmodQks = logmodQks
            retBks = B_ks
            end_N = new_n - 1
        else:
            start_n = new_n + 1

        prev_noise = new_noise
        prev_n = new_n
        prevlogmodQks = logmodQks
        prevBks = B_ks

        #start_n = new_n
        print("start_n at end of loop: ", start_n)
        print("end_N at end of loop: ", end_N)

    #add code to check if any n value lesser than the obtained n could result in the same or lower noise level
    #if (new_noise > target_noise_level and prev_noise <= target_noise_level):

    print("n in function before return: ", n)
    return n, retlogmodQks, retBks

parameter_selector()
