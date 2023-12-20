#!/bin/bash
python3 simulation_one_time.py $1 --num_servers 8 --cpus 17 --mem 24576 --workload_ratios 50,40,50 --remotemem --until 15 --size 6000 --max_far $2 --use_shrink  --ratios 1:0:1
python3 simulation_one_time.py $1 --num_servers 8 --cpus 17 --mem 24576 --workload_ratios 60,50,60 --remotemem --until 15 --size 6000 --max_far $2 --use_shrink  --ratios 1:0:1
python3 simulation_one_time.py $1 --num_servers 8 --cpus 17 --mem 24576 --workload_ratios 70,65,70 --remotemem --until 15 --size 6000 --max_far $2 --use_shrink  --ratios 1:0:1 
python3 simulation_one_time.py $1 --num_servers 8 --cpus 17 --mem 24576 --workload_ratios 75,80,75 --remotemem --until 15 --size 6000 --max_far $2 --use_shrink  --ratios 1:0:1
python3 simulation_one_time.py $1 --num_servers 8 --cpus 18 --mem 32768 --until 150 --size 600 
python3 simulation_one_time.py $1 --num_servers 9 --cpus 18 --mem 32768 --until 150 --size 600 
python3 simulation_one_time.py $1 --num_servers 1 --cpus 64 --mem $((262144+$2)) --until 150 --size 600 