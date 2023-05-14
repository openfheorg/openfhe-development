#!/usr/bin/python

from math import log2, floor, sqrt, ceil, exp

k = 16
w = 10

#1024#2048#4096
#548#1848#2048

N = 4096
n = 1848
Bg = 2**11
dg = 8

sigmafresh = sqrt(((4*k*N)/3)*3.2*3.2 + (3.2*3.2))
sigmabrk = sqrt((2*k*dg*N*Bg*Bg*sigmafresh*sigmafresh)/12)
sigmaak = sqrt(k*sigmafresh*sigmafresh)
kappa = N*(1-(exp(-n/N)))
sigmaacc = sqrt(dg*N*Bg*Bg*(2*n*sigmabrk*sigmabrk + (kappa + (N-kappa)/w)*sigmaak*sigmaak)/12)

print(log2(sigmaacc))

#GINX

u = 2
sigmasqaccginx = sqrt((2*u*dg*n*N*(Bg**2)*sigmabrk*sigmabrk)//6)
print(log2(sigmasqaccginx))


dr = 3
Br = 32
sigmasqaccap = sqrt((dr*(1-(1/Br))*dg*n*N*(Bg**2)*sigmabrk*sigmabrk)//6)
print(log2(sigmasqaccap))
