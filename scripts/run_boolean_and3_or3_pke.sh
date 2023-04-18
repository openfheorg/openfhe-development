#!/bin/bash

for k in {1..150}
do
  echo "iteration "$k
  bin/examples/binfhe/pke/boolean-3-AND-OR-pke #single threaded
done
