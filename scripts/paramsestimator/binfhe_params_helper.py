#!/usr/bin/python

from math import log2, floor, sqrt, ceil, erfc
from statistics import stdev
import random
import sys
import os
#import paramstable as stdparams
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
                               "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "dual_hybrid", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)
    else:
        estimateval = LWE.estimate(params, red_cost_model=RC.BDGL16, deny_list=[
                               "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "dual_hybrid", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)

    usvprop = floor(log2(estimateval['usvp']['rop']))
    dualrop = floor(log2(estimateval['dual']['rop']))
    decrop = floor(log2(estimateval['bdd']['rop']))
    print(estimateval)
    return min(usvprop, dualrop, decrop)

#generate dim, mod pairs for a given security level
def generate_stdsec_dim_mod(expected_sec_level, dim, mod_start = 0, is_quantum = True):

    #analytical estimate from Appendix C.1 of https://eprint.iacr.org/2012/099.pdf

    if (mod_start != 0):
        mod = mod_start

    sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)

    if (sec_level_from_estimator >= expected_sec_level):
        return dim, mod
    else:
        while (True or done):
            if (sec_level_from_estimator >= expected_sec_level):
                done = True
                break
            else:
                mod = mod/2
                sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)
                print("mod ", mod)
                print("sec_level ", sec_level_from_estimator)

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

    #also need to check if starting from a lower than possible mod - when the above condition is satisfied but not optimal

    if (modified and sec_level_from_estimator < expected_sec_level):
    	print("cannot find optimal params")
    	dim1 = 0
    	mod1 = 0

    return dim1, mod1


#optimized dim, mod values with least decryption failure rate
def choose_params_with_dim_mod_noise(exp_sec_level, param_set, exp_dec_fail, comp, is_quantum=True):

    ptmod = 2*comp
    ctmod = param_set.q

    noise = get_noise_from_cpp_code(param_set)
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
    print("choose_params_with_dim_mod_noise first dec_fail_rate first ", dec_fail_rate)

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

    dimopt2 = 0
    modopt2 = 0
    ctr = 0
    extraopt = True
    while ((dec_fail_rate - exp_dec_fail) < -10) or ctr > 5:
        mod1 = mod1/2
        dimopt2, modopt2 = optimize_params_security(exp_sec_level, dimopt1, mod1, True, False, isPowerOfTwo(dimopt1), is_quantum)
        noise = get_noise_from_cpp_code(param_set, dimopt2, modopt2)
        dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
        print("dec_fail_rate in second loop ", dec_fail_rate)
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
def choose_params_digit_size(exp_sec_level, param_set, exp_dec_fail, comp, optimize_Bg, optimize_Bks, is_quantum=True):
    ptmod = 2*comp
    ctmod = param_set.q

    noise = get_noise_from_cpp_code(param_set)
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
    print("dec_fail_rate first ", dec_fail_rate)

    dim, mod = get_dim_mod(param_set)
    B_g = 2**param_set.B_g
    B_ks = 2**param_set.B_ks

    B_g1 = B_g
    B_ks1 = B_ks

    print("B_g, B_ks before optimize: ", B_g, B_ks)

    if (optimize_Bg and (not optimize_Bks)):
        while ((dec_fail_rate > exp_dec_fail) or (B_g1/B_g == 16)):
            B_g1 = B_g1/4
            noise = get_noise_from_cpp_code(param_set, dim, mod, B_g1)
            dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
            print("B_g, B_ks before optimize: ", B_g, B_ks)
            print("dec_fail_rate in loop ", dec_fail_rate)
    elif ((not optimize_Bg) and optimize_Bks):
        while ((dec_fail_rate > exp_dec_fail) or (B_ks1/B_ks == 16)):
            B_ks1 = B_ks1/4
            noise = get_noise_from_cpp_code(param_set, dim, mod, B_g, B_ks1)
            dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
            print("B_g, B_ks before optimize: ", B_g, B_ks1)
            print("dec_fail_rate in loop ", dec_fail_rate)

    return B_g, B_ks


def get_noise_from_cpp_code(param_set, num_of_samples):

    filenamerandom = random.randrange(500)

    dim_n = param_set.n #n
    mod_q = param_set.q #mod_q
    mod_logQ = param_set.logQ  #mod_Q numberBits
    dim_N = param_set.N  # cyclOrder/2
    Qks = param_set.Qks #Qks modKS
    B_g = param_set.B_g #gadgetBase
    B_ks = param_set.B_ks #baseKS
    B_rk = param_set.B_rk #baseRK
    sigma = param_set.sigma #sigma stddev
    print("get_noise_from_cpp_code paramset dim mod Bg Bks: ", param_set_name, dim, mod, B_g, B_ks)
    bashCommand = "../palisade_versions/openfhenonvector7mar23finalfix/scripts/run_boolean_and3_or3_script.sh " + " " + str(dim_n) + " " + str(mod_q)+ " " + str(dim_N) + " " + str(logQ)+ " " + str(Qks) + " " + str(B_g) + " " + str(B_ks) + " " + str(B_rk) + " " + str(sigma) + " > out_file_" + str(filenamerandom) + " 2>noise_file_" + str(filenamerandom)

    print(bashCommand)
    os.system(bashCommand)
    # parse noise values and compute stddev
    noise=[]
    with open("noise_file_"+str(filenamerandom)) as file:
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

def get_target_noise(decryption_failure, ptmod, ctmod, comp):
    num = ctmod/(2*ptmod)
    denom = sqrt(2*comp)

    val = erfcinv(decryption_failure)
    target_noise = num/(denom*val)
    return target_noise

def isPowerOfTwo(n):
    if (n == 0):
        return False
    return (ceil(log2(n)) == floor(log2(n)))

def get_dim_mod(paramset):
    print("get_dim_mod paramset.n ", paramset.n)
    print("get_dim_mod params.Qks ", paramset.Qks)
    dim = paramset.n
    mod = 2**(paramset.Qks)

    return dim, mod

'''
def fit_data(data):
    var('a,b')
    model(x) = a*x+b
    fitline = find_fit(data,model)
    return fitline
'''
#def run_time_complexity_estimate(dim, Q, B_g):
#    d_g = Q/B_g

#    2*dim*(d_g+1)
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
###dim, mod = choose_params_with_dim_mod_noise(128, stdparams.STD128Q_OPT_3, -32, 6, 3)

###print("here after modulus, dimension optimization")
###print(dim, mod)
#stdparams.paramsDict["STD128Q_OPT_3_nQks1"][1] = dim
#stdparams.paramsDict["STD128Q_OPT_3_nQks1"][2] = mod

###stdparams.STD128Q_OPT_3.n = dim
###stdparams.STD128Q_OPT_3.Qks = log2(mod)

# then optimize B_g, B_ks for lower noise
###B_gres, B_ksres = choose_params_digit_size(128, stdparams.STD128Q_OPT_3, -32, 6, 3, True, False) #change p to 2*comp
###print("here after B_g optimization")
###B_gres1, B_ksres1 = choose_params_digit_size(128, stdparams.STD128Q_OPT_3, -32, 6, 3, False, True)
###print("here after B_ks optimization")
###print("B_g, B_ks 1st set optimize B_g: ", B_gres, B_ksres)
###print("B_g, B_ks 2nd set optimize B_ks: ", B_gres1, B_ksres1)
'''
for n in [800, 900]:
    dimres, modres = optimize_params_security(128, n, 2**30, False, True, False, False) #classical
    #dimres, modres = optimize_params_security(256, n, 2**15, False, True, False, True) #quantum
    print("n dimres modres: ", n, dimres, log2(modres))
'''
for n in [1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000, 2100]:
    dimres, modres = optimize_params_security(128, n, 2**40, False, True, False, False) #classical
    #dimres, modres = optimize_params_security(256, n, 2**35, False, True, False, True) #quantum
    print("n dimres modres: ", n, dimres, log2(modres))


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
