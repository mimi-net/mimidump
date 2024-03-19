# mimidump

![License](https://img.shields.io/github/license/mimi-net/mimidump)
[![Build](https://github.com/mimi-net/mimidump/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/mimi-net/mimidump/actions/workflows/build.yml)
[![Check](https://github.com/mimi-net/mimidump/actions/workflows/check.yml/badge.svg?branch=main)](https://github.com/mimi-net/mimidump/actions/workflows/check.yml)

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

## Development

### Automatically format code

```sh
clang-format -i mimidump.c
```

### Lint code

```sh
clang-tidy mimidump.c
```

### Pre-commit

#### Install pre-commit-hooks

```sh
pre-commit install
```

#### Run manually

```sh
pre-commit run --all-files --color always --verbose
```
