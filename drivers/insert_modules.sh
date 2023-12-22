sudo insmod rpage_allocator.ko
sudo insmod fastswap_rdma.ko sport=50000 sip="10.10.1.2" cip="10.10.1.1" nq=32
sudo insmod fastswap.ko