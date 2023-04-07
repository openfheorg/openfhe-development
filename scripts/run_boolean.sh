#!/bin/bash

for k in {1..150}
do
  echo "iteration "$k
  bin/examples/binfhe/boolean-2-AND-OR #single threaded
done
