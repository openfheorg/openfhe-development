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

    dist_type = int(input("Enter Distribution (0 = HEStd_uniform, 1 = HEStd_error, 2 = HEStd_ternary): "))
    helperfncs.test_range(dist_type, 0, 2)

    exp_sec_level = int(input("Enter Security level (0 = 128, 1 = 192, 2 = 256): "))
    helperfncs.test_range(sec_level, 0, 2)

    is_quantum = int(input("Include quantum attack estimates for security? (0 = False, 1 = True): "))
    helperfncs.test_range(is_quantum, 0, 1)

    exp_decryption_failure = int(input("Enter expected decryption failure rate (as a power of 2, for example, enter -32 for 2^-32 failure rate): "))

    num_of_inputs = int(input("Enter expected number of inputs to the boolean gate: "))


    #Set ringsize n, Qks, N, Q based on the security level

        usint numberBits; #Q
        usint cyclOrder; #2N
        usint latticeParam; #n
        usint mod;  #q

        usint modKS; #Qks
        #double stdDev;
        usint baseKS; #B_ks

        usint gadgetBase; #B_g
        #usint baseRK;

    while ringsize <= 32768:
        set_r=0
        set_qk=0
        print("---\nadjusting parameters for ringsize: ", ringsize)

        logQ = stdlat.LogQ[(dist_type, ringsize, sec_level)]

        if(optimize_r):
            for this_r in range(math.ceil(logQ/3.0), 0, -1):
            	if (logQ%this_r == 0):
	                if(scheme=="indcpa"):
        	            this_d = helperfncs.find_d_indcpa(logQ, ringsize, p, this_r)
        	        elif(scheme=="fixednf"):
        	            this_d = helperfncs.find_d_fixednoise(logQ, ringsize, p, this_r)

        	        if (this_d >= min_hops):
        	            r = this_r
        	            set_r=1
        	            print("resulting r ", r, "d ", this_d, " satisfies min hops, stopping")
        	            break

        else:
            this_r=1
            if(scheme=="indcpa"):
                this_d = helperfncs.find_d_indcpa(logQ, ringsize, p, this_r)
            elif(scheme=="fixednf"):
                this_d = helperfncs.find_d_fixednoise(logQ, ringsize, p, this_r)
            if (this_d >= min_hops):
                r = this_r
                set_r=1
                print("resulting r ", r, "d ", this_d, " satisfies min hops, stopping")



        #verify Q is ok
        if(set_r==1):
            if(scheme=="indcpa"):
                set_qk=1
                qk = helperfncs.find_qk_indcpa(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 60)
            elif(scheme=="fixednf"):
                set_qk=1
                qk = helperfncs.find_qk_fixednoise(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 476)
            elif(scheme=="psnf"):
                set_qk=1
                qk = helperfncs.find_qk_noiseflooding_ps(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 476)
            elif(scheme=="hybridpsnf"):
                set_qk=1
                qk = helperfncs.find_qk_noiseflooding_hybrid_ps(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 476)
            elif(scheme=="dvr_psnf"):
                set_qk=1
                qk = helperfncs.find_qk_dvr_ps(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 476)
            elif(scheme=="trapdoor_psnf"):
                set_qk=1
                qk = helperfncs.find_qk_trapdoor_ps(min_hops, ringsize, p, r, lwl_k = logQ, upl_k = 476)

        if(set_qk==1):
            if (qk <= logQ):
                print("resulting qk: ", qk, " <= logQ: ",logQ, "  satisfies security")
                break

            # if we get here qk is too big we need to move to a larger ring size
            print("resulting qk: ", qk, " > logQ: ",logQ, " does not satisfy security")
            print("increasing ringsize in an attempt to satisfy security")
        ringsize = ringsize *2

    if(scheme=="indcpa"):
        max_hops = helperfncs.find_d_indcpa(logQ, ringsize, p, r) - 1
    elif(scheme=="fixednf"):
        max_hops = helperfncs.find_d_fixednoise(logQ, ringsize, p, r) - 1
    elif(scheme=="psnf"):
        max_hops = helperfncs.find_d_noiseflooding_ps(logQ, ringsize, p, r) - 1
    elif(scheme=="hybridpsnf"):
        max_hops = helperfncs.find_d_noiseflooding_hybrid_ps(logQ, ringsize, p, r) - 1
    elif(scheme=="dvr_psnf"):
        max_hops = helperfncs.find_d_dvr_ps(logQ, ringsize, p, r) - 1
    elif(scheme=="trapdoor_psnf"):
        max_hops = helperfncs.find_d_trapdoor_ps(logQ, ringsize, p, r) - 1

    print("final parameters")
    print("dist_type: ",dist_type)
    print("sec_level: ", sec_level)
    print("decryption failure rate: ", ringsize)
    print("requested payload_bits: ", payload_bits)
    print("max payload_bits: ", ringsize*math.log2(p))
    print("p: ", p)
    print("min_hops: ", min_hops)
    print("max_hops (upto 2^60): ", max_hops)
    print("min_depth: ", min_depth)
    print("ringsize: ", ringsize)
    print("r: ", r)
    print("logQ: ", logQ)
    print("logQ/r: %4.1f" % (logQ/r))


#example call to function parameter_selector
#parameter_selector("indcpa", False)
#parameter_selector("fixednf", False)
#parameter_selector("psnf", False)
#parameter_selector("hybridpsnf", False)
#parameter_selector("dvr_psnf", False)
#parameter_selector("trapdoor_psnf", True)
#parameter_selector(mode, digit_optimize)
helperfncs.find_d_indcpa(27,1024,2,6)
helperfncs.find_d_indcpa(27,1024,2,9)
helperfncs.find_d_fixednoise(54,2048,65536,18)
