# mimidump
Packet sniffer for miminet

## Dependencies

* [libpcap](https://www.tcpdump.org/)
* [libbsd](https://libbsd.freedesktop.org/wiki/)

## Build

```sh
make
```

## Install

```sh
sudo make prefix=/usr install
```

## Usage example

```sh
sudo mimidump eth0 eth0.pcap eth0_out.pcap
```
