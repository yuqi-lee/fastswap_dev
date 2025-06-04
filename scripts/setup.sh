sudo sh -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled"
sudo sh -c "echo never > /sys/kernel/mm/transparent_hugepage/defrag"

if [ ! -f "./syscall" ]; then
    gcc syscall.c -o syscall
fi

sudo ./syscall

sudo swapon -p 999 /mydata/swapfile