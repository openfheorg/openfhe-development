#!/usr/bin/python

from math import log2, floor, sqrt, ceil, erfc
from statistics import stdev
import sys
import os
sys.path.insert(0, '/home/sara/lattice-estimator')
from estimator import *


def call_estimator(dim, mod, num_threads, is_quantum = True):
    ternary_uniform_1m1 = dim//3;

    params = LWE.Parameters(n=dim, q=mod, Xs=ND.SparseTernary(
        dim, ternary_uniform_1m1, ternary_uniform_1m1), Xe=ND.DiscreteGaussian(3.19))
        
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

#optimize dim, mod for an expected security level
def optimize_params_security(expected_sec_level, dim, mod, optimize_dim=False, is_dim_pow2=True, optimize_mod=True, is_quantum = True):
    dim1 = dim
    mod1 = mod
    dimlog = log2(dim)
    modified = False
    sec_level_from_estimator = call_estimator(dim, mod, num_threads)
    done = False
    
    while (sec_level_from_estimator < expected_sec_level or done):
        modified = True
        if (optimize_dim and (not optimize_mod)):
            dim1 = dim+15
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
def choose_params_with_dim_mod_noise(exp_sec_level, param_set, exp_dec_fail, dim, mod, ptmod, ctmod, comp, is_quantum, is_dim_pow2=True):
    #dimN, modQks = optimize_params_security(128, dim, mod, False, True, False, True)
    noise = get_noise_from_cpp_code(param_set, dim, mod, "", "noise_file_name")
    dec_fail_rate = get_decryption_failure(noise, ptmod, ctmod, comp)
    
    if (dec_fail_rate > exp_dec_fail):
        mod1 = mod*(2**4)
        dim1, mod1 = optimize_params_security(expected_sec_level, dim, mod, False, is_dim_pow2, True, is_quantum)
        sec_level_from_estimator_dim = optimize_params_security(expected_sec_level, dim, mod, True, is_dim_pow2, False, is_quantum)
    
    return dim1, mod1, dim2, mod2

'''
#optimize accumulator digit size or key switching digit size to lower noise
def choose_params_digit_size():
    sec_without_Bg_opt
    sec_with_Bg_opt
    return B_g, B_ks
'''
    
def get_noise_from_cpp_code(param_set, dim, mod, script, noise_file):    
    #arglist = 'arg1 arg2 arg3'
    bashCommand = "../palisade_versions/openfhenonvector7mar23finalfix/scripts/run_boolean_and3_or3.sh " + param_set + " " + str(dim) + " " + str(mod) + " > out_file 2 > " + noise_file
    print(bashCommand)
    os.system(bashCommand)
    # parse noise values and compute stddev
    noise=[]
    with open(noise_file) as file:
        for line in file:
            noise.append(line.rstrip())
    print(stdev(noise))
    return stdev(noise)
    
def get_decryption_failure(noise_stddev, ptmod, ctmod, comp):
    num = ctmod/(2*ptmod)
    denom = sqrt(2*comp)
    return log2(erfc(num/denom))

# estimate_params(n=1024, q=2048, Qks=2^16, security_level=128, quantum/classical=true, logBg=7, logBks=5, decryption_failure_rate=-32, native_word_bound=64, num_threads):

num_threads = 8

sec_level_from_estimator = call_estimator(2048, 2**50, num_threads);
print(sec_level_from_estimator)

N = 2048
Q = 2**50

n = 1024
Qks = 2**25
'''
# verify security of N, Q
dimN, modQ = optimize_params_security(128, N, Q, False, True, False, True)

# verify security of n, Qks and optimize
dimn, modQks = optimize_params_security(128, n, Qks, False, True, True, True)
'''
# verify security of n, Qks and optimize
dimn1, modQks1 = optimize_params_security(128, n, Qks, True, True, False, True)

# verify security of n, Qks and optimize
dimn2, modQks2 = optimize_params_security(128, 585, 2**15, True, False, False, True)

choose_params_with_dim_mod_noise(128, "STD128Q_3", -32, dimn2, modQks2, 6, 4096, 3, True)

'''
print("first set")
print(dimN)
print(log2(modQ))

print("second set")
print(dimn)
print(log2(modQks))
'''
print("third set")
print(dimn1)
print(log2(modQks1))

print("fourth set")
print(dimn2)
print(log2(modQks2))

# now verify the decryption rate and optimize the n, Qks params -- higher Qks gives lower noise and better decryption failure


# then optimize B_g, B_ks for lower noise

# ---------------------------------------------------------------------------------
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
