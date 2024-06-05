from pymemcache.client import base
import psutil
import os

def find_process_id_by_name(keyword):
    """
    Find the process ID (PID) of a running process by its name.

    :param process_name: The name of the process to find.
    :return: A list of PIDs of processes with the specified name.
    """
    process_ids = []
    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmdline = ' '.join(proc.info['cmdline'])
            if keyword in cmdline:
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# Example usage
process_name = 'memcached'
process = -1
process = find_process_id_by_name(process_name)


cgroup_path = "/cgroup2"

# Name of the new cgroup
cgroup_name = "memcached"

# Path to the new cgroup
new_cgroup_path = os.path.join(cgroup_path, cgroup_name)

# Create the new cgroup
os.makedirs(new_cgroup_path, exist_ok=True)

# Set the memory limit (in bytes)
with open(os.path.join(new_cgroup_path, "memory.high"), "w") as f:
    f.write("12G")  

with open(os.path.join(new_cgroup_path, "cgroup.procs"), "w") as f:
    f.write(str(process.pid))


client = base.Client(('127.0.0.1', 11211))

for i in range(4096*10240):
    key = f'key{i}'
    value = 'x' * 512 
    client.set(key, value)

print("预加载完成")
