#!/bin/bash

dim_n=$1
mod_q=$2
dim_N=$3
mod_logQ=$4
mod_Qks=$5
B_g=$6
B_ks=$7
B_rk=$8
sigma=$9
num_samples=$10

:'
for k in {1..50}
do
  echo "iteration "$k
  if [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -n "$B_g" ] && [ -n "$B_ks" ]
  then
    echo "here 1"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -g $B_g -b B_ks
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -z "$B_g" ] && [ -n "$B_ks" ]
  then
    echo "here 2"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -b B_ks
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -n "$B_g" ] && [ -z "$B_ks" ]
  then
    echo "here 3"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -g B_g
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -z "$B_g" ] && [ -z "$B_ks" ]
  then
    echo "here 4"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod
  elif [ -n "$param" ] && [ -z "$dim" ] && [ -z "$mod" ] && [ -z "$B_g" ] && [ -z "$B_ks" ]
  then
    echo "here 5"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param
  else
    echo "param set not provided"
  fi
done
'
for k in {1..$10}
do
  echo "iteration "$k
  if [ -n "$dim_n" ] && [ -n "$dim_N" ] && [ -n "$mod_q" ] && [ -n "$mod_Q" ] && [ -n "$mod_Qks" ] && [ -n "$B_g" ] && [ -n "$B_ks" ] && [ -n "$B_rk" ] && [ -n "$sigma" ]
  then
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -n $dim_n -q $mod_q -N $dim_N -Q $mod_logQ -k $mod_Qks -g $B_g -b $B_ks -r $B_rk -s $sigma
  else
    echo "argument missing"
  fi
done
