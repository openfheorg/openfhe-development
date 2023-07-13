#!/usr/bin/python

from math import log2, floor, sqrt, ceil, erfc
from scipy.special import erfcinv
from statistics import stdev
import random
import sys
import os
import io
from time import sleep
#import paramstable as stdparams
import paramstable as stdparams
sys.path.insert(0, '/home/sara/lattice-estimator')
from estimator import *

num_threads = 8
syspath = "/home/sara/scriptparamsbinfhe24may23"

def restore_print():
    # restore stdout
    sys.stdout = sys.__stdout__
    #text_trap.getvalue()

def block_print():
    text_trap = io.StringIO()
    sys.stdout = text_trap

#find analytical estimate for starting point of modulus for the estimator
def get_mod(dim, exp_sec_level):
    #get linear relation coefficients for log(modulus) and dimension for the input security level
    a = stdparams.paramlinear[exp_sec_level][1]
    b = stdparams.paramlinear[exp_sec_level][2]

    modapp = a*dim + b
    mod = ceil(modapp)
    return mod

#calls the lattice-estimator to get the work factor for known attacks; currently only for ternary secrets. todo later: add other secret distributions
def call_estimator(dim, mod, secret_dist="ternary", num_threads = 1, is_quantum = True):
    #ternary_uniform_1m1 = dim//3;
    params = LWE.Parameters(n=dim, q=mod, Xs=ND.Uniform(-1, 1, dim), Xe=ND.DiscreteGaussian(3.19))
    if secret_dist == "uniform":
        params = LWE.Parameters(n=dim, q=mod, Xs=ND.UniformMod(mod), Xe=ND.DiscreteGaussian(3.19))
    elif secret_dist == "error":
        params = LWE.Parameters(n=dim, q=mod, Xs=ND.DiscreteGaussian(3.19), Xe=ND.DiscreteGaussian(3.19))
    elif secret_dist == "ternary":
        params = LWE.Parameters(n=dim, q=mod, Xs=ND.Uniform(-1, 1, dim), Xe=ND.DiscreteGaussian(3.19))
    else:
        print("Invalid distribution for secret")

    if is_quantum:
        block_print()
        estimateval = LWE.estimate(params, red_cost_model=RC.LaaMosPol14, deny_list=[
                               "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "dual_hybrid", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)
        restore_print()
    else:
        block_print()
        estimateval = LWE.estimate(params, red_cost_model=RC.BDGL16, deny_list=[
                               "bkw", "bdd_hybrid", "bdd_mitm_hybrid", "dual_hybrid", "dual_mitm_hybrid", "arora-gb"], jobs=num_threads)
        restore_print()

    usvprop = floor(log2(estimateval['usvp']['rop']))
    dualrop = floor(log2(estimateval['dual']['rop']))
    decrop = floor(log2(estimateval['bdd']['rop']))

    return min(usvprop, dualrop, decrop)

#optimize dim, mod for an expected security level - this is specifically for the dimension n, and key switch modulus Qks in FHEW. Increasing Qks helps reduce the bootstrapped noise
def optimize_params_security(expected_sec_level, dim, mod, secret_dist = "ternary", num_threads = 1, optimize_dim=False, optimize_mod=True, is_dim_pow2=True, is_quantum = True):
    dim1 = dim
    dimlog = log2(dim)
    #sec_level_from_estimator = call_estimator(dim, mod, num_threads, is_quantum)
    done = False

    while done is False:
        try:
            sec_level_from_estimator = call_estimator(dim, mod, secret_dist, num_threads, is_quantum)
            done = True
        except:
            mod = mod*2
            pass
    done = False
    mod1 = mod

    modifieddim = False
    modifiedmod = False
    #loop to adjust modulus if given dim, modulus provide less security than target
    while (sec_level_from_estimator < expected_sec_level or done):
        if (optimize_dim and (not optimize_mod)):
            modifieddim = True
            dim1 = dim1+15
            if ((dim1 >= 2*dim) and (not is_dim_pow2)):
                done = True
            elif is_dim_pow2:
                dim1 = 2*dim
            sec_level_from_estimator = call_estimator(dim1, mod, secret_dist, num_threads, is_quantum)
        elif ((not optimize_dim) and optimize_mod):
            mod1 = mod1/2
            try:
                sec_level_from_estimator = call_estimator(dim, mod1, secret_dist, num_threads, is_quantum)
                modifiedmod = True
            except:
                return 0, 0

    #also need to check if starting from a lower than possible mod - when the above condition is satisfied but not optimal
    #loop to adjust modulus if given dim, modulus provide more security than target
    prev_sec_estimator = sec_level_from_estimator
    sec_level_from_estimator_new = sec_level_from_estimator
    prev_mod = mod1
    modifieddimmore = False
    modifiedmodmore = False
    while True:
        prev_sec_estimator = sec_level_from_estimator_new
        if (optimize_dim and (not optimize_mod)):
            modifieddimmore = True
            dim1 = dim1-15
            if ((dim1 <= 500) and (not is_dim_pow2)):
                done = True
            elif is_dim_pow2:
                dim1 = dim/2
            sec_level_from_estimator_new = call_estimator(dim1, mod, secret_dist, num_threads, is_quantum)
        elif ((not optimize_dim) and optimize_mod):
            mod1 = mod1*2
            try:
                sec_level_from_estimator_new = call_estimator(dim, mod1, secret_dist, num_threads, is_quantum)
                modifiedmodmore = True
            except:
                return 0, 0
        if (((prev_sec_estimator >= expected_sec_level) and (sec_level_from_estimator_new < expected_sec_level)) or done):
            break

    if (modifiedmodmore and prev_sec_estimator >= expected_sec_level):
        mod1 = mod1/2

    if ((modifieddim or modifiedmod) and sec_level_from_estimator < expected_sec_level):
        dim1 = 0
        mod1 = 0
        print("cannot find optimal params")

    return dim1, mod1

def get_noise_from_cpp_code(param_set, num_of_samples, perfNumbers = False):

    filenamerandom = random.randrange(500)

    dim_n = param_set.n #n
    mod_q = param_set.q #mod_q
    mod_logQ = param_set.logQ  #mod_Q numberBits
    dim_N = param_set.N  # cyclOrder/2
    mod_Qks = param_set.Qks #Qks modKS
    B_g = param_set.B_g #gadgetBase
    B_ks = param_set.B_ks #baseKS
    B_rk = param_set.B_rk #baseRK
    sigma = param_set.sigma #sigma stddev
    bashCommand = syspath + "/scripts/run_boolean_and3_or3_script.sh " + str(dim_n) + " " + str(mod_q)+ " " + str(dim_N) + " " + str(mod_logQ)+ " " + str(mod_Qks) + " " + str(B_g) + " " + str(B_ks) + " " + str(B_rk) + " " + str(sigma) + " " + str(num_of_samples) + " " + syspath + " > out_file_" + str(filenamerandom) + " 2>noise_file_" + str(filenamerandom)

    print(bashCommand)
    os.system(bashCommand)
    # parse noise values and compute stddev
    noise=[]
    with open("noise_file_"+str(filenamerandom)) as file:
        for line in file:
            noise.append(float(line.rstrip()))

    perfnum = get_performance("out_file_"+ str(filenamerandom))
    if perfNumbers:
        return stdev(noise), perfnum
    else:
        return stdev(noise)

def get_performance(filename):
    #stdparams.performanceNumbers(bootstrapKeySize, keyswitchKeySize, ciphertextSize, bootstrapKeygenTime, evalbingateTime)
    perf = {}
    with open(filename) as file:
        for line in file:
            s1 = line.split(":")
            ### need python 3.10 or higher to use match instead of ifelse
            if (s1[0] == "BootstrappingKeySize"):
                perf.update({"BootstrappingKeySize": s1[1] + " bytes"})
            elif(s1[0] == "KeySwitchingKeySize"):
                perf.update({"KeySwitchingKeySize": s1[1] + " bytes"})
            elif(s1[0] == "CiphertextSize"):
                perf.update({"CiphertextSize": s1[1] + " bytes"})
            elif(s1[0] == "BootstrapKeyGenTime"):
                perf.update({"BootstrapKeyGenTime": s1[1]})
            elif(s1[0] == "EvalBinGateTime"):
                perf.update({"EvalBinGateTime": s1[1]})

    return perf



def get_decryption_failure(noise_stddev, ptmod, ctmod, comp):
    num = ctmod/(2*ptmod)
    denom = sqrt(2*comp)*noise_stddev
    val = erfc(num/denom)
    if (val == 0):
        retval = 0
    else:
    	retval = log2(val)
    return retval

def get_target_noise(decryption_failure, ptmod, ctmod, comp):
    num = ctmod/(2*ptmod)
    denom = sqrt(2*comp)

    val = erfcinv(2**decryption_failure)
    target_noise = num/(denom*val)
    return target_noise

def isPowerOfTwo(n):
    if (n == 0):
        return False
    return (ceil(log2(n)) == floor(log2(n)))

def get_dim_mod(paramset):
    dim = paramset.n
    mod = 2**(paramset.Qks)

    return dim, mod

def test_range(val, low, hi):
    if val in range(low, hi+1):
        return
    else:
        msg = f"input not in valid range ({low} - {hi})"
        raise Exception(msg)

'''
#generate dim, mod pairs for a given security level
def generate_stdsec_dim_mod(expected_sec_level, dim, mod_start = 10, secret_dist = "ternary", num_threads = 1, is_quantum = True):

    #analytical estimate from Appendix C.1 of https://eprint.iacr.org/2012/099.pdf

    if (mod_start != 0):
        mod = mod_start

    sec_level_from_estimator = call_estimator(dim, mod, secret_dist, num_threads, is_quantum)

    if (sec_level_from_estimator >= expected_sec_level):
        return dim, mod
    else:
        while (True or done):
            if (sec_level_from_estimator >= expected_sec_level):
                done = True
                break
            else:
                mod = mod/2
                sec_level_from_estimator = call_estimator(dim, mod, secret_dist, num_threads, is_quantum)
                print("mod ", mod)
                print("sec_level ", sec_level_from_estimator)

    return dim, log2(mod)

#optimized dim, mod values with least decryption failure rate - this can be ignored (deleted later)
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

#optimize accumulator digit size or key switching digit size to lower noise - this can be ignored (deleted later)
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
'''
###########################################################################################33
#To be cleaned up before merging PR
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

for n in [1300, 1400, 1500, 1600, 1700, 1800, 1900, 2000, 2100]:
    dimres, modres = optimize_params_security(128, n, 2**40, False, True, False, False) #classical
    #dimres, modres = optimize_params_security(256, n, 2**35, False, True, False, True) #quantum
    print("n dimres modres: ", n, dimres, log2(modres))
'''

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
