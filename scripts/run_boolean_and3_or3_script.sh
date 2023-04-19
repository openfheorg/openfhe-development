#!/bin/bash

param=$1
dim=$2
mod=$3
B_g=$4
B_ks=$5

for k in {1..50}
do
  echo "iteration "$k
  if [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -n "$B_g" ] && [ -n "$B_ks" ] 
  then
    echo "here 1"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -g $B_g -b B_ks #single threaded
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -z "$B_g" ] && [ -n "$B_ks" ] 
  then
    echo "here 2"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -b B_ks #single threaded
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -n "$B_g" ] && [ -z "$B_ks" ] 
  then
    echo "here 3"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod -g B_g #single threaded
  elif [ -n "$param" ] && [ -n "$dim" ] && [ -n "$mod" ] && [ -z "$B_g" ] && [ -z "$B_ks" ] 
  then
    echo "here 4"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param -n $dim -k $mod #single threaded
  elif [ -n "$param" ] && [ -z "$dim" ] && [ -z "$mod" ] && [ -z "$B_g" ] && [ -z "$B_ks" ] 
  then
    echo "here 5"
    /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p $param #single threaded
  else  
    echo "param set not provided"
  fi
done
