import argparse
import zlib

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, Ether
from scapy.layers.inet6 import IPv6
from scapy.layers.sctp import SCTP
from scapy.layers.l2 import Dot1Q

parser = argparse.ArgumentParser(description='Recv packets.')

parser.add_argument('-f', '--file_name', type=str)

parser.add_argument('-ckload', '--check_load', action='store_true')
parser.add_argument('-ckip4', '--check_ip', action='store_true')
parser.add_argument('-cktcp', '--check_tcp', action='store_true')
parser.add_argument('-ckudp', '--check_udp', action='store_true')

# 获取L2参数
parser.add_argument('--l2_dst', action='store_true')
parser.add_argument('--l2_src', action='store_true')
parser.add_argument('--l2_type', action='store_true')
parser.add_argument('--dot1q_vlan', action='store_true')

# 获取ipv4参数
parser.add_argument('--ipv4_version', action='store_true')
parser.add_argument('--ipv4_ihl', action='store_true')
parser.add_argument('--ipv4_tos', action='store_true')
parser.add_argument('--ipv4_len', action='store_true')
parser.add_argument('--ipv4_id', action='store_true')
parser.add_argument('--ipv4_flags', action='store_true')
parser.add_argument('--ipv4_frag', action='store_true')
parser.add_argument('--ipv4_ttl', action='store_true')
parser.add_argument('--ipv4_proto', action='store_true')
parser.add_argument('--ipv4_chksum', action='store_true')
parser.add_argument('--ipv4_src', action='store_true')
parser.add_argument('--ipv4_dst', action='store_true')
parser.add_argument('--ipv4_options', action='store_true')

# 获取ipv6参数
parser.add_argument('--ipv6_version', action='store_true')
parser.add_argument('--ipv6_tc', action='store_true')
parser.add_argument('--ipv6_fl', action='store_true')
parser.add_argument('--ipv6_nh', action='store_true')
parser.add_argument('--ipv6_hlim', action='store_true')
parser.add_argument('--ipv6_src', action='store_true')
parser.add_argument('--ipv6_dst', action='store_true')

# 获取udp参数
parser.add_argument('--udp_sport', action='store_true')
parser.add_argument('--udp_dport', action='store_true')
parser.add_argument('--udp_chksum', action='store_true')
parser.add_argument('--udp_len', action='store_true')

# 获取sctp参数
parser.add_argument('--sctp_sport', action='store_true')
parser.add_argument('--sctp_dport', action='store_true')
parser.add_argument('--sctp_chksum', action='store_true')

# 获取tcp参数
parser.add_argument('--tcp_sport', action='store_true')
parser.add_argument('--tcp_dport', action='store_true')
parser.add_argument('--tcp_seq', action='store_true')
parser.add_argument('--tcp_ack', action='store_true')
parser.add_argument('--tcp_dataofs', action='store_true')
parser.add_argument('--tcp_reserved', action='store_true')
parser.add_argument('--tcp_flags', action='store_true')
parser.add_argument('--tcp_window', action='store_true')
parser.add_argument('--tcp_chksum', action='store_true')
parser.add_argument('--tcp_urgptr', action='store_true')
parser.add_argument('--tcp_options', action='store_true')


def check_load(pkt):
    crc_value = int.from_bytes(pkt.load[:2], 'big')
    payload = pkt.load[2:]
    if crc_value == (zlib.crc32(payload) & 0xFFFF):
        print('payload校验成功')
    else:
        print('payload校验失败')


def check_ip(pkt):
    chksum_ip = pkt[IP].fields.pop('chksum')
    pkt[IP].raw_packet_cache = None
    new_pkt = IP(bytes(pkt.getlayer(IP)))
    if chksum_ip == new_pkt[IP].chksum:
        print('ip字段checksum校验成功')
    else:
        print('ip字段checksum校验失败')


def check_tcp(pkt):
    chksum_tcp = pkt[TCP].fields.pop('chksum')
    pkt[TCP].raw_packet_cache = None
    new_pkt = TCP(bytes(pkt.getlayer(TCP)))
    if chksum_tcp == new_pkt[TCP].chksum:
        print('tcp字段checksum校验成功')
    else:
        print('tcp字段checksum校验失败')


def check_udp(pkt):
    chksum_udp = pkt[UDP].fields.pop('chksum')
    pkt[UDP].raw_packet_cache = None
    new_pkt = UDP(bytes(pkt.getlayer(UDP)))
    if chksum_udp == new_pkt[UDP].chksum:
        print('udp字段checksum校验成功')
    else:
        print('udp字段checksum校验失败')


class RecvPacket(object):
    def __init__(self):
        self.file_name = ''
        self.check_load = False
        self.check_ip = False
        self.check_tcp = False
        self.check_udp = False

    def recv_packet(self):
        packets = rdpcap(self.file_name)
        for pkt in packets:
            self.check_param(pkt)
            self.get_param(pkt)

    def check_param(self, pkt):
        if self.check_load:
            check_load(pkt)
        if self.check_ip:
            check_ip(pkt)
        if self.check_tcp:
            check_tcp(pkt)
        if self.check_udp:
            check_udp(pkt)

    def get_param(self, pkt):
        for attr, value in self.__dict__.items():
            try:
                if value:
                    if attr.startswith('l2_'):
                        param = pkt[Ether].fields[attr[3:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('dot1q_'):
                        param = pkt[Dot1Q].fields[attr[6:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('ipv4_'):
                        param = pkt[IP].fields[attr[5:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('ipv6_'):
                        param = pkt[IPv6].fields[attr[5:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('udp_'):
                        param = pkt[UDP].fields[attr[4:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('sctp_'):
                        param = pkt[SCTP].fields[attr[5:]]
                        print(f'{attr}: {param} ')
                    elif attr.startswith('tcp_'):
                        param = pkt[TCP].fields[attr[4:]]
                        print(f'{attr}: {param} ')
            except IndexError as e:
                print(f'{e}')


sp = RecvPacket()
parser.parse_args(namespace=sp)
sp.recv_packet()
