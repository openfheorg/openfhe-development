#!/usr/bin/python

#Generate dimension and modulus for every security level - classical and quantum

import paramstable as stdparams
import binfhe_params_helper as helperfncs
import math

sec_levels = [128, 192, 256]
dim_vals = [4096, 8192, 16384, 32768]
def generate_sec_table():
    for sec in sec_levels:
        for dim in dim_vals:
            dimresq, modresq = helperfncs.generate_stdsec_dim_mod(sec, dim, True) #is_quantum = True
            print("quantum ", sec, " dim, mod: ", dimresq, modresq)
            dimres, modres = helperfncs.generate_stdsec_dim_mod(sec, dim, False) #is_quantum = True
            print("classical ", sec, " dim, mod: ", dimres, modres)

generate_sec_table()
