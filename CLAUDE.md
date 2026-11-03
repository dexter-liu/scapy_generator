# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A Scapy-based packet generator tool for constructing and sending various network protocol packets, including standard protocols (IP, TCP, UDP, IPv6, SCTP, ICMP) and custom RDMA (RoCE) packet layers.

## Quick Start

```bash
# Send basic UDP packet
python pkt_send.py -i eth0 -pt udp4

# Send RDMA packet
python pkt_send.py -i eth0 -pt rdma --rdma_type send_first

# Receive packets
python pkt_recv.py -i eth0 -c 10
```

## File Structure

- `pkt_send.py` / `pkt_send_ext.py` - Main packet generation and sending tools
- `pkt_recv.py` - Packet capture tool
- `pkt_parser.py` - Parse hex dump from tcpdump
- `pkt_dscp.py` - DSCP marking tests
- `pkt_ip4_options.py` - IPv4 options and extension tests
- `util/layers.py` - Custom Scapy layer definitions (BTH, RDETH, DETH, AETH, RETH for RDMA)

## Supported Packet Types

**Standard protocols:** `ip`, `ip6`, `udp4`, `udp6`, `tcp4`, `tcp6`, `sctp4`, `icmp`, `icmp6`, `arp`, `vlan`, `qinq`, `lacp`, `pause`, `pfc`

**RDMA types:** `send_first`, `send_middle`, `send_last`, `send_only`, `rdma_write_*`, `rdma_read_*`, `acknowledge`, `connect_*`, `disconnect_*`

## Common Commands

```bash
# Send with specific parameters
python pkt_send.py -i eth0 -pt tcp4 --tcp_sport 1234 --tcp_dport 80 --ipv4_src 192.168.1.1

# Send with IPv6 extension headers
python pkt_send_ext.py -i eth0 -pt tcp6 --ipv6_ext "frag:id=0x64,m=1,offset=0"

# Generate packet list by length range
python pkt_send.py -i eth0 -pt udp4 -m plist --pkt_len_list "64-1200,1500-9000"

# Random mode - generate multiple packets with random values
python pkt_send.py -i eth0 -pt udp4 -m random -rc 100

# Save packets to pcap
python pkt_send.py -i eth0 -pt udp4 -s output.pcap

# Print packet details
python pkt_send.py -i eth0 -pt udp4 -p
```

## Architecture Notes

- **Custom RDMA layers** in `util/layers.py` define BTH, RDETH, DETH, AETH, RETH headers with `guess_payload_class()` for dynamic payload resolution based on OpCode
- **Layer binding** uses Scapy's `bind_layers()` to establish protocol relationships (UDP port 61300-61399 → BTH)
- **Packet generation flow**: `init_packet()` → `generate_packet()` → `set_param()` → `send_packet()`
- **Parameter injection**: `set_param()` uses reflection to match argument prefixes (e.g., `tcp_*` → TCP layer)
- `pkt_send_ext.py` extends `pkt_send.py` with additional protocols (ether, arp, icmp6, qinq, lacp, IPv6 extension headers)
