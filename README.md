# mimidump
Packet sniffer for miminet

# Make
gcc mimidump.c -l pcap -o mimidump

# Example
sudo ./mimidump eth0 eth0.pcap eth0_out.pcap
