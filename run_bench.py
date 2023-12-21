import os
import subprocess
import time

pid = os.getpid()
# os.sched_setaffinity(pid, {1,2,3,4})

# Path to the cgroup v2 hierarchy
cgroup_path = "/cgroup2"

# Name of the new cgroup
cgroup_name = "my_cgroup_14"

# Path to the new cgroup
new_cgroup_path = os.path.join(cgroup_path, cgroup_name)

# Create the new cgroup
os.makedirs(new_cgroup_path, exist_ok=True)

# Set the memory limit (in bytes)
with open(os.path.join(new_cgroup_path, "memory.high"), "w") as f:
    f.write("12G")  

# Run the command as a subprocess
#command = ["python", "/users/YuqiLi/my_higgs.py"]
#command = ["/users/YuqiLi/cfm/quicksort/quicksort", "16384"]
#command = ["zip", "/users/YuqiLi/swaptest.zip" ,"/users/YuqiLi/HIGGS.csv"]
command = ["python", "/users/YuqiLi//transformers/examples/pytorch/language-modeling/run_clm.py" \
    "--model_name_or_path", "gpt2" \
    "--dataset_name", "wikitext" \
    "--dataset_config_name", "wikitext-2-raw-v1" \
    "--per_device_train_batch_size", "8" \
    "--per_device_eval_batch_size", "8" \
    "--do_train" \
    "--do_eval" \
    "--output_dir", "/tmp/test-clm-16G"]
start_time = time.time()
process = subprocess.Popen(command, stderr=subprocess.PIPE)

# Add the process to the cgroup
with open(os.path.join(new_cgroup_path, "cgroup.procs"), "w") as f:
    f.write(str(process.pid))

# Wait for the process to finish
process.wait()
end_time = time.time()

if process.returncode == 0:
    print("workload finish successfully.\n")
else:
    #stderr = process.stderr.read()
    print("workload exit with error code: ", process.returncode)



# Print the runtime of the command
print(f"Runtime: {end_time - start_time} seconds")

# Remove the cgroup after the command has finished
# os.rmdir(new_cgroup_path)