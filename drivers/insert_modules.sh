sudo insmod rpage_allocator.ko
sudo insmod fastswap_rdma.ko sport=50000 sip="130.127.134.40" cip="130.127.134.65" nq=8
sudo insmod fastswap.ko