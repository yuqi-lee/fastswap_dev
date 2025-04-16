sudo modprobe ib_core
sudo modprobe rdma_cm
sudo modprobe ib_cm
sudo insmod ./rswap-client.ko sip=10.10.1.5 sport=50000 rmsize=32