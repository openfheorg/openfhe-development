#!/bin/bash

for k in {1..5}
do
  echo "iteration "$k
  ../palisade_versions/openfhenonvector7mar23finalfix/build/bin/examples/binfhe/boolean-3-AND-OR #single threaded
done
