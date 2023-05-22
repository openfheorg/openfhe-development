#!/bin/bash

# Pablo Echegorri
# 5-3-2020
# pabloechegorri@gmail.com

##
## Copy disclaimer here below

# benchmark  examples  extras

BENCHMARKS=/openfhe-development/build/bin/benchmark/*
RESULTS=/var/www/html/benchmark.html

echo "<!DOCTYPE html>" >> $RESULTS
echo "<html><body>" >> $RESULTS
for benchmark in $BENCHMARKS
do
    echo "Running $benchmark"
    echo "<pre>" >> $RESULTS
    $benchmark > >(tee -a $RESULTS) 2> >(tee -a $RESULTS >&2)
    echo -e "\n</pre>" >> $RESULTS

done
echo "</body></html>" >> $RESULTS

