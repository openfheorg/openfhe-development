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

sec_levels = [128, 192, 256]
dim_vals = [512, 1024, 2048, 4096, 8192, 16384, 32768]
def generate_sec_table():
    for sec in sec_levels:
        for dim in dim_vals:
            dimresq, modresq = helperfncs.generate_stdsec_dim_mod(sec, dim, True) #is_quantum = True
            print("quantum ", sec, " dim, mod: ", dimresq, modresq)
            dimres, modres = helperfncs.generate_stdsec_dim_mod(sec, dim, False) #is_quantum = True
            print("classical ", sec, " dim, mod: ", dimres, modres)

generate_sec_table()
