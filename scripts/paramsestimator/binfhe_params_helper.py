#!/usr/bin/python

from math import log2, floor, sqrt, ceil, erfc
from statistics import stdev
import sys
import os
import paramstable as stdparams
sys.path.insert(0, '/home/sara/lattice-estimator')
from estimator import *

num_threads = 8

#calls the lattice-estimator to get the work factor for known attacks; currently only for ternary secrets. todo later: add other secret distributions
def call_estimator(dim, mod, num_threads, is_quantum = True):
    #ternary_uniform_1m1 = dim//3;

    params = LWE.Parameters(n=dim, q=mod, Xs=ND.Uniform(-1, 1, dim), Xe=ND.DiscreteGaussian(3.19))

    if is_quantum:
        estimateval = LWE.estimate(params, red_cost_model=RC.LaaMosPol14, deny_list=[
                               "bkw", "bdd", "bdd_mitm_hybrid", "dual", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)
    else:
        estimateval = LWE.estimate(params, red_cost_model=RC.BDGL16, deny_list=[
                               "bkw", "bdd", "bdd_mitm_hybrid", "dual", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)

    usvprop = floor(log2(estimateval['usvp']['rop']))
    dualhybridrop = floor(log2(estimateval['dual_hybrid']['rop']))
    dechybridrop = floor(log2(estimateval['bdd_hybrid']['rop']))
    print(estimateval)
    return min(usvprop, dualhybridrop, dechybridrop)

#generate dim, mod pairs for a given security level
def generate_stdsec_dim_mod(expected_sec_level, dim, is_quantum = True):

    mod = 2**floor(log2(dim))
    mod_next = 2*mod

    sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)
    sec_level_from_estimator_next = call_estimator(dim, mod_next, num_threads, is_quantum)

    if (sec_level_from_estimator > expected_sec_level) and (sec_level_from_estimator_next < expected_sec_level):
        return dim, mod
    else:
        while (True):
	    #sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)
            if (sec_level_from_estimator > expected_sec_level) and (sec_level_from_estimator_next < expected_sec_level):
                break
            else:
                mod = mod*2
                mod_next = 2*mod
                sec_level_from_estimator = sec_level_from_estimator_next
                sec_level_from_estimator_next = call_estimator(dim, mod_next, num_threads, is_quantum)
                print("sec_level ", sec_level_from_estimator, "sec_level_next ", sec_level_from_estimator_next)


    return dim, log2(mod)

#optimize dim, mod for an expected security level - this is specifically for the dimension n, and key switch modulus Qks in FHEW. Increasing Qks helps reduce the bootstrapped noise
def optimize_params_security(expected_sec_level, dim, mod, optimize_dim=False, optimize_mod=True, is_dim_pow2=True, is_quantum = True):
    dim1 = dim
    mod1 = mod
    dimlog = log2(dim)
    modified = False
    sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)
    done = False

    while (sec_level_from_estimator < expected_sec_level or done):
        modified = True
        if (optimize_dim and (not optimize_mod)):
            dim1 = dim1+15
            if ((dim1 >= 2*dim) and (not is_dim_pow2)):
                done = true
            elif is_dim_pow2:
                dim1 = 2*dim
            sec_level_from_estimator = call_estimator(dim1, mod, num_threads, is_quantum)
        elif ((not optimize_dim) and optimize_mod):
            mod1 = mod1/2
            sec_level_from_estimator = call_estimator(dim, mod1, num_threads, is_quantum)

    if (modified and sec_level_from_estimator < expected_sec_level):
    	print("cannot find optimal params")
    	dim1 = 0
    	mod1 = 0

    return dim1, mod1


#optimized dim, mod values with least decryption failure rate
def choose_params_with_dim_mod_noise(exp_sec_level, param_set, exp_dec_fail, ptmod, ctmod, comp, is_quantum=True):
    #dimN, modQks = optimize_params_security(128, dim, mod, False, True, False, True)

    noise = get_noise_from_cpp_code(param_set)
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
    print("dec_fail_rate first ", dec_fail_rate)

    dim, mod = get_dim_mod(param_set)
    dimopt1 = dim
    modopt1 = mod
    mod1 = mod
    while ((dec_fail_rate > exp_dec_fail) or (mod1/mod == 16)):
        mod1 = mod1*2
        dimopt1, modopt1 = optimize_params_security(exp_sec_level, dim, mod1, True, False, isPowerOfTwo(dim), is_quantum)
        noise = get_noise_from_cpp_code(param_set, dimopt1, modopt1)
        dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
        print("dec_fail_rate in loop ", dec_fail_rate)

    #try to optimize - could be made optional
    mod1 = modopt1
    ctr = 0
    extraopt = True
    while ((dec_fail_rate - exp_dec_fail) < -10) or ctr > 5:
        mod1 = mod1/2
        dimopt2, modopt2 = optimize_params_security(exp_sec_level, dimopt1, mod1, True, False, isPowerOfTwo(dimopt1), is_quantum)
        noise = get_noise_from_cpp_code(param_set, dimopt2, modopt2)
        dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
        print("dec_fail_rate in loop ", dec_fail_rate)
        ctr=ctr+1
        if (dec_fail_rate > exp_dec_fail):
            print("cannot optimize further - try adjusting digit dize for tighter parameters")
            extraopt = False
            break

    print(dimopt1, modopt1)
    print(dimopt2, modopt2)

    dimopt = dimopt1
    modopt = modopt1
    if extraopt:
        dimopt = dimopt2
        modopt = modopt2

    return dimopt, modopt

#optimize accumulator digit size or key switching digit size to lower noise
def choose_params_digit_size(exp_sec_level, param_set, exp_dec_fail, ptmod, ctmod, comp, optimize_Bg, optimize_Bks, is_quantum=True):
    noise = get_noise_from_cpp_code(param_set, "noise_file_name")
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
    print("dec_fail_rate first ", dec_fail_rate)
    dim, mod = get_dim_mod(param_set)
    B_g1 = B_g

    print("B_g, B_ks before optimize: ", B_g, B_ks)
    while ((dec_fail_rate > exp_dec_fail) or (B_g1/B_g == 16)):
        B_g1 = B_g1/4
        noise = get_noise_from_cpp_code(param_set, dim, mod, B_g1)
        dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
        print("dec_fail_rate in loop ", dec_fail_rate)

    return B_g, B_ks


def get_noise_from_cpp_code(param_set, dim=0, mod=0, B_g = 0, B_ks = 0, noise_file = "noise_file_name"):
    #arglist = 'arg1 arg2 arg3'
    #bashCommand = "../palisade_versions/openfhenonvector7mar23finalfix/scripts/run_boolean_and3_or3_script.sh " + param_set + " > out_file 2>" + noise_file
    bashCommand = "../palisade_versions/openfhenonvector7mar23finalfix/scripts/run_boolean_and3_or3_script.sh " + param_set + " " + str(dim) + " " + str(mod) + " " + str(B_g) + " " + str(B_ks) + " > out_file 2>" + noise_file

    print(bashCommand)
    os.system(bashCommand)
    # parse noise values and compute stddev
    noise=[]
    with open(noise_file) as file:
        for line in file:
            noise.append(float(line.rstrip()))
    print("noise", stdev(noise))
    return stdev(noise)

def get_decryption_failure(noise_stddev, ptmod, ctmod, comp):
    num = ctmod/(2*ptmod)
    denom = sqrt(2*comp)*noise_stddev
    print("num", num)
    print("denom", denom)
    val = erfc(num/denom)
    if (val == 0):
        retval = 0
    else:
    	retval = log2(val)
    return retval

def isPowerOfTwo(n):
    if (n == 0):
        return False
    return (ceil(log2(n)) == floor(log2(n)))

def get_dim_mod(paramset):
    params = stdparams.paramsDict[paramset]

    dim = params[1]
    mod = 2**params[2]

    return dim, mod
#********************end of helper functions***********************************

# verify security of n, Qks and optimize
#dimn1, modQks1 = optimize_params_security(128, 585, 2**16, True, False, isPowerOfTwo(585), True)

#print("optimized sets")
#print(dimn1)
#print(log2(modQks1))
#print("****")
#dimn2, modQks2 = optimize_params_security(128, 585, 2**16, False, True, isPowerOfTwo(585), True)

#print(dimn2)
#print(log2(modQks2))
#print("****")

# now verify the decryption rate and optimize the n, Qks params -- higher Qks gives lower noise and better decryption failure
#4 input gates
#choose_params_with_dim_mod_noise(128, "STD128Q_OPT_3_nQks1", -32, 8, 4096, 4)
#2 input gates
#dim, mod = choose_params_with_dim_mod_noise(128, "STD128Q_OPT_3_nQks1", -32, 4, 4096, 2)

#stdparams.paramsDict["STD128Q_OPT_3_nQks1"][1] = dim
#stdparams.paramsDict["STD128Q_OPT_3_nQks1"][2] = mod
# then optimize B_g, B_ks for lower noise
#choose_params_digit_size(128, "STD128Q_OPT_3_nQks1", -32, 6, 4096, 3, True, False)
# ---------------------------------------------------------------------------------
# estimate_params(n=1024, q=2048, Qks=2^16, security_level=128, quantum/classical=true, logBg=7, logBks=5, decryption_failure_rate=-32, native_word_bound=64, num_threads):
#sec_level_from_estimator = call_estimator(2048, 2**50, num_threads);
#print(sec_level_from_estimator)
'''
# verify security of N, Q
dimN, modQ = optimize_params_security(128, N, Q, False, True, False, True)
# verify security of n, Qks and optimize
dimn, modQks = optimize_params_security(128, n, Qks, False, True, True, True)

# verify security of n, Qks and optimize
dimn1, modQks1 = optimize_params_security(128, n, Qks, True, True, False, True)
'''

'''
print("first set")
print(dimN)
print(log2(modQ))
print("second set")
print(dimn)
print(log2(modQks))
print("third set")
print(dimn1)
print(log2(modQks1))
'''


'''
while (sec_level_from_estimator < expected_sec_level):
        if(((mod le 32) and (mod1 gt 32)) or ((mod le 64) and (mod1 gt 64))):
    done = true
'''
'''
Theoretical noise estimate
n = 1024
q = 1024
Qks = 2**25
N = 2048
Q = 2**50
logQ = log2(Q)
logQks = log2(Qks)
logBg = 25
logBks = 5
sec_level_from_estimator = call_estimator(n, Qks, num_threads);
print(sec_level_from_estimator)
u = 2
sigmasq = 3.19*3.19
Bg = 2**logBg
Bks = 2**logBks
dg = ceil(logQ/logBg)
dks = ceil(logQks/logBks)
sigmasqacc = (2*u*dg*n*N*(Bg**2)*sigmasq)//6
psigmasqacc = ((Qks**2)/(Q**2))*sigmasqacc
sigmasqKS = sigmasq*N*dks
sigmasqMS1 = (N + 2)//6
noise_sum = psigmasqacc + sigmasqKS + sigmasqMS1
sigmasq_MS2 = (n + 2)//6
noise_estimate_GINX = sqrt((q**2/Qks**2)*(noise_sum) + sigmasq_MS2)
print(noise_estimate_GINX)
'''
