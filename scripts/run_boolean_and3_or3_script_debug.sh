#!/bin/bash

for k in {1..50}
do
  /home/sara/palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR-script -p STD128Q_OPT_3 #single threaded
done
