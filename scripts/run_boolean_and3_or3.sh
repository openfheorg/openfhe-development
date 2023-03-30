#!/bin/bash

for k in {1..1000}
do
  echo "iteration "$k
  bin/examples/binfhe/boolean-4-AND-OR #single threaded
done
