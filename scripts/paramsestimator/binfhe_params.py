#!/usr/bin/python

'''Approach for determining parameters for binfhe
1) Pick bootstrapping method
2) Pick secret distribution
3) Pick security level
4) Set expected decryption failure rate
5) Specify max number of inputs to a boolean gate
Measure bootstrap keygen/evalbingate time, and throughput (bootstrap keygen size, keyswitching key size, ciphertext size) and document.
'''

import paramstable as stdparams
import binfhe_params_helper as helperfncs
from math import log2, floor, sqrt, ceil

def parameter_selector():
    print("Parameter selectorfor FHEW like schemes")

    #bootstrapping technique
    dist_type = int(input("Enter Bootstrapping technique (0 = GINX, 1 = AP, 2 = LMKDCEY): "))
    helperfncs.test_range(dist_type, 0, 2)

    secret_dist = int(input("Enter Secret distribution (0 = uniform, 1 = error, 2 = ternary): "))
    helperfncs.test_range(secret_dist, 0, 2)

    exp_sec_level = input("Enter Security level (STD128, STD128Q, STD192, STD192Q, STD256, STD256Q): ")

    #is_quantum = int(input("Include quantum attack estimates for security? (0 = False, 1 = True): "))
    #helperfncs.test_range(is_quantum, 0, 1)

    exp_decryption_failure = int(input("Enter expected decryption failure rate (for example, enter -32 for 2^-32 failure rate): "))

    num_of_inputs = int(input("Enter expected number of inputs to the boolean gate: "))

    num_of_samples = int(input("Enter expected number of samples to estimate noise: "))

    d_ks = int(input("Enter key switching digit size: "))

    num_threads = int(input("Enter number of threads that can be used to run the lattice-estimator: "))

    #processing parameters based on the inputs
    if (exp_sec_level[-1] == "Q"):
        is_quantum = True
    else:
        is_quantum = False

    if (secret_dist == 0):
        secret_dist_des = "uniform"
    elif (secret_dist == 1):
        secret_dist_des = "error"
    elif (secret_dist == 2):
        secret_dist_des = "ternary"

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
            modulus_q = ringsize_N
            loopq2N = False
            while (modulus_q <= 2*ringsize_N):
                #other variables
                lattice_n = 500 # for stdnum security, could set to ringsize_N/2 #start with this value and binary search on n to find optimal parameter set

                logmodQksu = helperfncs.get_mod(lattice_n, exp_sec_level) #find analytical estimate for starting point of Qks
                logmodQu = helperfncs.get_mod(ringsize_N, exp_sec_level)

                #check security by running the estimator and adjust modulus if needed
                dimn, modulus_Qks = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], lattice_n, 2**logmodQksu, secret_dist_des, num_threads, False, True, False, is_quantum)
                dimN, modulus_Q = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], ringsize_N, 2**logmodQu, secret_dist_des, num_threads, False, True, False, is_quantum)

                if (dimn > dimN):
                    print("estimator adjusted to invalid lattice dimension greater than ring dimension N")
                    break
                elif ((dimn == 0) or (modulus_Qks == 0)):
                    print("initial lattice dimension too small to run the estimator for this security level, increasing initial value")

                while ((dimn == 0) and (modulus_Qks == 0)):
                    lattice_n = lattice_n + 100
                    logmodQksu = helperfncs.get_mod(lattice_n, exp_sec_level)
                    dimn, modulus_Qks = helperfncs.optimize_params_security(stdparams.paramlinear[exp_sec_level][0], lattice_n, 2**logmodQksu, secret_dist_des, num_threads, False, True, False, is_quantum)

                #check again
                if ((dimn > dimN) or (dimn == 0) or (modulus_Qks == 0)):
                    print("starting lattice dimension is 0 or greater than large N")
                    break

                logmodQks = log2(modulus_Qks)
                logmodQ = log2(modulus_Q)

                #this is added since Qks is declared as usint in openfhe
                if (logmodQks >= 32):
                    logmodQks = 30
                while(logmodQks > logmodQ):
                    logmodQks = logmodQks - 1

                modulus_Qks = 2**logmodQks
                B_g = 2**ceil(logmodQ/d_g)
                B_ks = 2**ceil(logmodQks/d_ks)

                while (B_ks >= 128):# or ()32gb limit on complexity:
                    B_ks = B_ks/2
                #create paramset object
                param_set_opt = stdparams.paramsetvars(lattice_n, modulus_q, ringsize_N, logmodQ, modulus_Qks, B_g, B_ks, B_rk, sigma)

                #optimize n, Qks to reduce the noise
                #compute target noise level for the expected decryption failure rate
                target_noise_level = helperfncs.get_target_noise(exp_decryption_failure, ptmod, modulus_q, num_of_inputs)
                print("Target noise for this iteration: ", target_noise_level)

                actual_noise = helperfncs.get_noise_from_cpp_code(param_set_opt, num_of_samples)##########################################################run script CPP###########

                if (actual_noise > target_noise_level):
                    opt_n, optlogmodQks, optB_ks = binary_search_n(lattice_n, ringsize_N, actual_noise, exp_sec_level, target_noise_level, num_of_samples, d_ks, param_set_opt)#lattice_n, ringsize_N)
                else:
                    opt_n = lattice_n

                if (opt_n != 0):
                    break
                elif ((opt_n == 0) and loopq2N):
                    break
                else:
                    modulus_q = modulus_q*2
                    loopq2N = True
                    print("increasing q to 2N to find parameters optimized for the input")

            if (opt_n != 0):
                break
            else:
                ringsize_N = ringsize_N*2
                print("increasing N to 2048 to find parameters optimized for the input")

        if (opt_n == 0):
            print("cannot find parameters for d_g: ", d_g)
        else:
            optQks = 2**optlogmodQks
            B_g = 2**ceil(logmodQ/d_g)

            param_set_final = stdparams.paramsetvars(opt_n, modulus_q, ringsize_N, logmodQ, optQks, B_g, optB_ks, B_rk, sigma)
            finalnoise, perf = helperfncs.get_noise_from_cpp_code(param_set_final, 1000, True)##########################################################run script CPP###########
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
            print("Performance: ", perf)


#add d_ks to the function
def binary_search_n(start_n, end_N, prev_noise, exp_sec_level, target_noise_level, num_of_samples, d_ks, params):
    n = 0

    retlogmodQks = 0
    retBks = 0
    found = False
    while(start_n <= end_N):
        new_n = floor((start_n + end_N)/2)

        logmodQks = helperfncs.get_mod(new_n, exp_sec_level)
        if (logmodQks >= 32):
            logmodQks = 30

        while(logmodQks > params.logQ):
            logmodQks = logmodQks - 1

        params.n = new_n
        params.Qks = 2**logmodQks
        B_ks = 2**ceil(logmodQks/d_ks)
        while (B_ks >= 128):
            B_ks = B_ks/2

        params.B_ks = B_ks
        new_noise = helperfncs.get_noise_from_cpp_code(params, num_of_samples)

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

    #add code to check if any n value lesser than the obtained n could result in the same or lower noise level
    if ((found) and (new_n < prev_n)):
        params.Qks = 2**retlogmodQks
        params.Bks = retBks
        n, retlogmodQks, retBks = find_opt_n(new_n, prev_n, exp_sec_level, target_noise_level, num_of_samples, d_ks, params)

    return n, retlogmodQks, retBks

def find_opt_n(start_n, end_n, exp_sec_level, target_noise_level, num_of_samples, d_ks, params):
    opt_n = end_n
    optlogmodQks = log2(params.Qks)
    optBks = params.Bks
    while (start_n <= end_n):
        newopt_n = floor((start_n + end_n)/2)
        print("newopt n: ", newopt_n)

        logmodQks = helperfncs.get_mod(newopt_n, exp_sec_level)
        if (logmodQks >= 32):
            logmodQks = 30

        while(logmodQks > params.logQ):
            logmodQks = logmodQks - 1

        params.n = newopt_n
        params.Qks = 2**logmodQks
        B_ks = 2**ceil(logmodQks/d_ks)
        while (B_ks >= 128):
            B_ks = B_ks/2

        params.B_ks = B_ks
        new_noise = helperfncs.get_noise_from_cpp_code(params, num_of_samples)

        if (new_noise < target_noise_level):
            opt_n = newopt_n
            optlogmodQks = logmodQks
            optBks = B_ks
            end_n = newopt_n - 1
        else:
            start_n = newopt_n + 1


    return opt_n, optlogmodQks, optBks

def binary_search_n_Qks(start_n, end_N, prev_noise, exp_sec_level, target_noise_level, num_of_samples, d_ks, params):
    n = 0

    retlogmodQks = 0
    retBks = 0

    intlogmodQks = 0
    intBks = 0
    int_noise = 0
    initiallogQks = log2(params.Qks)
    while(start_n <= end_N):
        new_n = floor((start_n + end_N)/2)
        print("new n: ", new_n)
        params.n = new_n
        logmodQks = helperfncs.get_mod(new_n, exp_sec_level)

        while(logmodQks > params.logQ):
            logmodQks = logmodQks - 1

        if (logmodQks >= 32):
            logmodQks = 30

        startlogQks = initiallogQks

        endlogQks = logmodQks

        newlogmodQks = startlogQks
        #newlogmodQks = log2(startQks)

        found = False
        while(startlogQks <= endlogQks):
            params.Qks = 2**newlogmodQks
            B_ks = 2**ceil(newlogmodQks/d_ks)
            while (B_ks >= 128):
                B_ks = B_ks/2     # display in the final parameters if the d_ks value is different from input

            params.B_ks = B_ks
            new_noise = helperfncs.get_noise_from_cpp_code(params, num_of_samples)

            #if (new_noise > target_noise_level and prev_noise <= target_noise_level):
            if (new_noise <= target_noise_level):
                print("in qks search break if")
                found = True
                n = new_n
                intlogmodQks = prevlogmodQks
                intBks = prevBks
                int_noise = prev_noise
            prev_found = found

            if found:
                break

            if (new_noise <= target_noise_level):
                print("in qks search new noise < target noise")
                endlogQks = newlogmodQks - 1
            else:
                print("in qks search new noise > target noise")
                startlogQks = newlogmodQks + 1

            prevlogmodQks = newlogmodQks
            prevBks = B_ks
            prev_noise = new_noise

            newlogmodQks = ceil((startlogQks + endlogQks)/2)
            print("newlogmodQks: ", newlogmodQks)
            print("startlogQks: ", startlogQks)
            print("endlogQks: ", endlogQks)

        print("int_noise: ", int_noise)
        print("new_noise: ", new_noise)

        print("prev_found: ", prev_found)
        print("found: ", found)

        if (prev_found and (not found) and (new_noise <= int_noise)):
            end_N = new_n - 1
        elif (prev_found and (not found) and (new_noise > int_noise)):
            n = new_n
            retlogmodQks = intlogmodQks
            retBks = intBks
            break
        else:
            if (new_noise > target_noise_level):
                start_n = new_n + 1
            else:
                end_N = new_n - 1

        if (prev_found and (not found)):
            retlogmodQks = intlogmodQks
            retBks = intBks


    #add code to check if any n value lesser than the obtained n could result in the same or lower noise level
    #if (new_noise > target_noise_level and prev_noise <= target_noise_level):

    return n, retlogmodQks, retBks

parameter_selector()
