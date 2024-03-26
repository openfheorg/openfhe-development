#!/bin/bash

# Prompt the user for thread settings
read -p "Enter comma-separated thread settings (e.g., 1,2,4,8,...): " thread_settings

# Split the input into an array
IFS=',' read -ra threads <<< "$thread_settings"

echo "num_threads   | ringDim   | numLimbs  | encode (ms) | ptxt x ctxt (ms)  | (encode/ptxtxctxt) % | ctxt Add (ms)"

# Loop through each thread setting
for num_threads in "${threads[@]}"; do
    # Set OMP_NUM_THREADS
    export OMP_NUM_THREADS="$num_threads"

    # Run the benchmarking binary
    output=$(./build/bin/benchmark/bfv-encode-vs-ptxt-ctxt-benchmark)

    # Extract relevant information
    ring_dim=$(echo "$output" | grep -oP 'ring dimension \K\d+')
    num_ilparams=$(echo "$output" | grep -oP 'ILParams' | wc -l)
    encode_time=$(echo "$output" | grep -oP 'encode took: \K[\d.]+')
    ptxt_ctxt_time=$(echo "$output" | grep -oP 'ptxt-ctxt took: \K[\d.]+')
    ctxt_add_time=$(echo "$output" | grep -oP 'ctxt add  took: \K[\d.]+')

    # Calculate percentage
    percentage=$(bc <<< "scale=2; ($encode_time / $ptxt_ctxt_time) * 100")

    # Print the results
    # printf "%-13s | %-9s | %-9s | %-11s | %-15s | %s%% | %-11s\n" "$num_threads" "$ring_dim" "$num_ilparams" "$encode_time" "$ptxt_ctxt_time" "$percentage" "$ctxt_add_time"
    printf "%-13s | %-9s | %-9s | %-11s | %-17s | %-20s | %-10s \n" "$num_threads" "$ring_dim" "$num_ilparams" "$encode_time" "$ptxt_ctxt_time" "$percentage" "$ctxt_add_time"
done
