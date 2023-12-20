import os
import subprocess
import time

# Path to the cgroup v2 hierarchy
cgroup_path = "/cgroup2"

# Name of the new cgroup
cgroup_name = "my_cgroup_8"

# Path to the new cgroup
new_cgroup_path = os.path.join(cgroup_path, cgroup_name)

# Create the new cgroup
os.makedirs(new_cgroup_path, exist_ok=True)

# Set the memory limit (in bytes)
with open(os.path.join(new_cgroup_path, "memory.high"), "w") as f:
    f.write("7G")  

# Run the command as a subprocess
command = ["python3", "/users/YuqiLi/my_higgs.py"]
start_time = time.time()
process = subprocess.Popen(command)

# Add the process to the cgroup
with open(os.path.join(new_cgroup_path, "cgroup.procs"), "w") as f:
    f.write(str(process.pid))

# Wait for the process to finish
process.wait()
end_time = time.time()

# Print the runtime of the command
print(f"Runtime: {end_time - start_time} seconds")

# Remove the cgroup after the command has finished
# os.rmdir(new_cgroup_path)