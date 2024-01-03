sudo insmod rpage_allocator.ko
sudo insmod fastswap_rdma.ko sport=50000 sip="10.10.1.1" cip="10.10.1.2" nq=128
sudo insmod fastswap.ko