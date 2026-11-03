# -*- coding: utf-8 -*-
import argparse
import random
import zlib
from scapy.contrib.mac_control import MACControl, MACControlPause, MACControlClassBasedFlowControl
from scapy.contrib.slowprot import SlowProtocol
from scapy.contrib.lacp import LACP
from scapy.layers.inet import Ether, IP, TCP, UDP, ICMP, IPOption_NOP, IPOption_EOL, IPOption_LSRR, \
IPOption_RR, IPOption_SSRR
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.sctp import SCTP
from scapy.packet import Raw
from scapy.layers.l2 import Dot1Q, ARP
from scapy.sendrecv import sendp, send
from scapy.plist import PacketList
from scapy.utils import wrpcap
from scapy.volatile import RandShort, RandIP, RandMAC, RandIP6, RandString, RandNum

from util.layers import BTH, RDETH, DETH, AETH, RETH, ImmDt, MDETH, DSETH, FragHead, PCRC, ICRC, ops_with_DETH, \
    ops_with_RETH, ops_with_ImmDt, ops_with_AETH, ops_with_RDETH, d_op_codes

parser = argparse.ArgumentParser(description='Send packets.')
# 设置发包端口
parser.add_argument('-i', '--iface', dest='iface', required=True)

# 设置报文类型，暂时支持ipv4、ipv6、udp4、udp6、tcp4、tcp6、额外增加ethernet、arp、icmp6、vlan
# p_type ipv6修改为ip6
parser.add_argument('-pt', '--p_type', dest='p_type', required=True,
                    choices=['ip', 'ip6', 'udp4', 'udp6', 'tcp4', 'tcp6', 'sctp4', 'icmp', 'rdma', 'pfc', 'pause',
                             'ether', 'arp', 'icmp6', 'vlan', 'lacp', 'qinq'])

# 设置发包level,l2 for 'sendp' l3 for 'send'
parser.add_argument('-sl', '--send_level', default='l2', choices=['l2', 'l3'])

parser.add_argument('-m', '--mode', dest='mode', default='spec', choices=['spec', 'random', 'plist'])

# rdma类型
parser.add_argument('--rdma_type', dest='rdma_type', default=ops_with_RDETH[0], choices=ops_with_RDETH)

# 设置发包数，默认为1
parser.add_argument('-c', '--count', dest='count', type=int, default=1)
parser.add_argument('-rc', '--random_count', dest='random_count', type=int, help='random list count', default=1)
parser.add_argument('--random_payload', action='store_true', help='random payload')
# 是否打印每个报文
parser.add_argument('-p', '--print', dest='print_output', action='store_true', help='Print each packet')
# 是否保存构建的数据包
parser.add_argument('-s', '--save_path', dest='save_path', type=str)

# ethernet参数解析
parser.add_argument('--ether_dst', type=str)
parser.add_argument('--ether_src', type=str)
parser.add_argument('--ether_type', type=str)

# vlan参数解析
parser.add_argument('--vlan_prio', type=str, help='VLAN priority (0-7)')
parser.add_argument('--vlan_vlan', type=str, help='VLAN ID (0-4095)')
parser.add_argument('--vlan_type', type=str, help='VLAN type/ether type')
parser.add_argument('--qinq', action='store_true', help='qinq开关', default=False)

# arp参数解析
parser.add_argument('--arp_hwtype', type=str)
parser.add_argument('--arp_ptype', type=str)
parser.add_argument('--arp_hwlen', type=str)
parser.add_argument('--arp_plen', type=str)
parser.add_argument('--arp_op', type=str)
parser.add_argument('--arp_hwsrc', type=str)
parser.add_argument('--arp_psrc', type=str)
parser.add_argument('--arp_hwdst', type=str)
parser.add_argument('--arp_pdst', type=str)

# L2参数解析
parser.add_argument('--l2_dst', type=str)
parser.add_argument('--l2_src', type=str)
parser.add_argument('--l2_type', type=str)
# vlan参数解析已经有了
# parser.add_argument('--vlan', type=str)

# ipv4参数解析
parser.add_argument('--ipv4_version', type=str)
parser.add_argument('--ipv4_ihl')
parser.add_argument('--ipv4_tos', type=str)
parser.add_argument('--ipv4_len', type=str)
parser.add_argument('--ipv4_id', type=str)
parser.add_argument('--ipv4_flags', type=str)
parser.add_argument('--ipv4_frag', type=str)
parser.add_argument('--ipv4_ttl', type=str)
parser.add_argument('--ipv4_proto', type=str)
parser.add_argument('--ipv4_chksum', type=str)
parser.add_argument('--ipv4_src', type=str)
parser.add_argument('--ipv4_dst', type=str)
parser.add_argument('--ipv4_options', type=str, help="选项简写,多个选项用逗号分隔,支持NOP,RR,LSRR,SSRR,EOL")

# ipv6参数解析
parser.add_argument('--ipv6_version', type=str)
parser.add_argument('--ipv6_tc', type=str)
parser.add_argument('--ipv6_fl', type=str)
parser.add_argument('--ipv6_nh', type=str)
parser.add_argument('--ipv6_hlim', type=str)
parser.add_argument('--ipv6_src', type=str)
parser.add_argument('--ipv6_dst', type=str)
parser.add_argument('--userid_ipv6', type=str)

# udp参数解析
parser.add_argument('--udp_sport', type=str)
parser.add_argument('--udp_dport', type=str)
parser.add_argument('--udp_chksum', type=str)
parser.add_argument('--udp_len', type=str)

# sctp参数解析
parser.add_argument('--sctp_sport', type=str)
parser.add_argument('--sctp_dport', type=str)
parser.add_argument('--sctp_chksum', type=str)

# tcp参数解析
parser.add_argument('--tcp_sport', type=str)
parser.add_argument('--tcp_dport', type=str)
parser.add_argument('--tcp_seq', type=str)
parser.add_argument('--tcp_ack', type=str)
parser.add_argument('--tcp_dataofs')
parser.add_argument('--tcp_reserved', type=str)
parser.add_argument('--tcp_flags')  # flags S <class 'scapy.fields.FlagValue'>
parser.add_argument('--tcp_window', type=str)
parser.add_argument('--tcp_chksum', type=str)
parser.add_argument('--tcp_urgptr', type=str)
parser.add_argument('--tcp_options', type=bytes)

# icmpv6参数解析
parser.add_argument('--icmpv6_type', type=str)
parser.add_argument('--icmpv6_code', type=str)
parser.add_argument('--icmpv6_cksum', type=str)
parser.add_argument('--icmpv6_id', type=str)
parser.add_argument('--icmpv6_seq', type=str)
parser.add_argument('--icmpv6_data', type=str)

# BTH
# parser.add_argument('--bth_OpCode', type=str) # depend on rdma_type
parser.add_argument('--bth_SE', type=str)
parser.add_argument('--bth_version', type=str)
parser.add_argument('--bth_A', type=str)
parser.add_argument('--bth_Destination_QP', type=str)
parser.add_argument('--bth_PSN', type=str)

# RDETH
parser.add_argument('--rdeth_T', type=str)
parser.add_argument('--rdeth_C', type=str)
parser.add_argument('--rdeth_S', type=str)
parser.add_argument('--rdeth_I', type=str)
parser.add_argument('--rdeth_R', type=str)
parser.add_argument('--rdeth_P', type=str)
parser.add_argument('--rdeth_SegPSN', type=str)
parser.add_argument('--rdeth_iPSN', type=str)
parser.add_argument('--rdeth_MSN', type=str)
parser.add_argument('--rdeth_SRC_C_ID', type=str)
parser.add_argument('--rdeth_DST_C_ID', type=str)
parser.add_argument('--rdeth_TimestampValue', type=str)
parser.add_argument('--rdeth_TimestampEcho', type=str)

# DETH
parser.add_argument('--deth_Flags', type=str)
parser.add_argument('--deth_SourceQP', type=str)

# MDETH
parser.add_argument('--mdeth_DMAKey', type=str)
parser.add_argument('--mdeth_dma_length', type=str)

# DSETH
parser.add_argument('--dseth_offset', type=str)

# RETH
parser.add_argument('--reth_VirtualAddress', type=str)
parser.add_argument('--reth_R_Key', type=str)
parser.add_argument('--reth_DmaLength', type=str)

# AETH
parser.add_argument('--aeth_syndrome', type=str)
parser.add_argument('--aeth_MSN', type=str)

# IMMDT
parser.add_argument('--immdt_ImmediateData', type=str)

# FragHead
parser.add_argument('--fraghead_magic', type=str)
parser.add_argument('--fraghead_offset', type=str)
parser.add_argument('--fraghead_msn', type=str)
parser.add_argument('--fraghead_flag', type=str)
parser.add_argument('--fraghead_iPSN', type=str)

# raw_load
parser.add_argument('--load', type=str)
parser.add_argument('--random_load_size', type=str)
parser.add_argument('--crc_check', action='store_true')

# pkt len list
# pkt len长度为eth报文的总长度，ether+vlan+l3+l4+payload+fcs,不包括前导码
parser.add_argument('--pkt_len_list', type=str, help="plist mode,set pkt len by'64-1200,5000-9600'")


def random_ipv6(userid: str = None) -> RandIP6:
    """
    生成指定user id的随机ipv6地址
    @param userid: ipv6地址的63位到40位，ffff:ff
    @return:
    """
    if userid is None:
        return RandIP6()

    user_id = userid[:4] + ':' + userid[4:]
    temp = '*:*:*:*:' + user_id + ''.join(random.choices('0123456789abcdef', k=2)) + ':*:*'
    return RandIP6(temp)


class SendPacket(object):

    def __init__(self) -> None:
        self.mode = ''
        self.packet = None
        self.packet_list = PacketList()
        self.iface = ''
        self.send_level = ''
        self.p_type = ''
        self.rdma_type = ''
        self.deth_Flags = 0
        self.load = ''
        self.random_load_size = None
        self.crc_check = False
        self.count = 1
        self.random_count = 1
        self.print_output = False
        self.save_path = ''
        self.userid_ipv6 = None

    def init_packet(self):
        if self.random_load_size is not None:
            size = int(RandNum(0, int(self.random_load_size)))
            self.load = str(RandString(size=size))
        self.generate_packet()
        if self.print_output:
            if self.mode == 'random':
                for p in self.packet_list:
                    p.show2()
            else:
                self.packet.show2()
        if self.save_path:
            packet = self.packet
            if self.mode == 'random' or self.mode == 'plist':
                packet = self.packet_list
            wrpcap(self.save_path, packet)

    def generate_packet(self):
        # ether/arp/icmp6 added by liuchao
        if self.p_type == 'ether':
            self.packet = Ether()
            self.set_param(layer='Ether', ptype='ether')
        elif self.p_type == 'vlan':
            self.packet = Ether() / Dot1Q()
            self.set_param(layer='Ether', ptype='ether')
            self.set_param(layer='Dot1Q', ptype='vlan')
        elif self.p_type == 'qinq':
            self.packet = Ether() / Dot1Q() / Dot1Q()
            self.set_param(layer='Ether', ptype='ether')
            self.set_param(layer='Dot1Q', ptype='vlan')
        elif self.p_type == 'arp':
            if self.vlan_vlan:
                # self.packet = Ether() / Dot1Q(vlan=int(self.vlan_vlan)) / ARP()
                self.packet = Ether() / Dot1Q() / ARP()
                self.set_param(layer='Ether', ptype='ether')
                self.set_param(layer='Dot1Q', ptype='vlan')
                self.set_param(layer='ARP', ptype='arp')
            else:
                self.packet = Ether() / ARP()
                self.set_param(layer='Ether', ptype='ether')
                self.set_param(layer='ARP', ptype='arp')
        elif self.p_type == 'icmp6':
            self.packet = IPv6() / ICMPv6EchoRequest()
            self.set_param(layer='IPv6', ptype='ip6')
            self.set_param(layer='ICMPv6 Echo Request', ptype='icmp6')

        elif self.p_type == 'ip':
            self.packet = IP()
            self.set_param(layer='IP', ptype='ipv4')
        elif self.p_type == 'tcp4':
            self.packet = IP() / TCP()
            self.set_param(layer='IP', ptype='ipv4')
            self.set_param(layer='TCP', ptype='tcp')
        elif self.p_type == 'udp4':
            self.packet = IP() / UDP()
            self.set_param(layer='IP', ptype='ipv4')
            self.set_param(layer='UDP', ptype='udp')
        elif self.p_type == 'ip6':
            self.packet = IPv6()
            self.set_param(layer='IPv6', ptype='ip6')
        elif self.p_type == 'udp6':
            self.packet = IPv6() / UDP()
            self.set_param(layer='IPv6', ptype='ip6')
            self.set_param(layer='UDP', ptype='udp')
        elif self.p_type == 'tcp6':
            self.packet = IPv6() / TCP()
            self.set_param(layer='IPv6', ptype='ip6')
            self.set_param(layer='TCP', ptype='tcp')
        elif self.p_type == 'icmp':
            self.packet = IP() / ICMP()
            self.set_param(layer='IP', ptype='ipv4')
        elif self.p_type == 'sctp4':
            self.packet = IP() / SCTP()
            self.set_param(layer='IP', ptype='ipv4')
            self.set_param(layer='SCTP', ptype='sctp')
        elif self.p_type == 'pause':
            self.packet = MACControlPause()
        elif self.p_type == 'pfc':
            self.packet = MACControlClassBasedFlowControl()
        elif self.p_type == 'rdma':
            self.set_solar_packet()
        # 添加对lacp协议的支持
        elif self.p_type == 'lacp':
            self.packet = Ether(dst="01:80:c2:00:00:02", type=0x8809) / SlowProtocol() / LACP()
            self.set_param(layer='Ether', ptype='ether')

        if self.load and self.p_type not in ['rdma', 'ether']:
            payload = self.generate_raw_load_packet()
            self.packet = self.packet / Raw(load=payload)

        if self.send_level == 'l2':
            if self.p_type in ['pfc', 'pause']:
                self.packet = Ether(dst=MACControl.DEFAULT_DST_MAC) / self.packet
                # 添加ethernet层的参数
                self.set_param(layer='Ether', ptype='ether')
            
            # 比如ip/ipv6等包l2模式发送时, 给他们加上ether头和vlan头
            elif self.p_type not in ['ether', 'vlan', 'arp', 'lacp', 'qinq']:  # ether类型已经是以太网头，不需要再封装
                if self.vlan_vlan:
                    if self.qinq:
                        self.packet = Ether() / Dot1Q() / Dot1Q(vlan=210, prio=7) / self.packet
                        self.set_param(layer='Ether', ptype='ether')
                        self.set_param(layer='Dot1Q', ptype='vlan')
                    else:
                        # self.packet = Ether() / Dot1Q(vlan=int(self.vlan_vlan)) / self.packet
                        self.packet = Ether() / Dot1Q() / self.packet
                        self.set_param(layer='Ether', ptype='ether')
                        self.set_param(layer='Dot1Q', ptype='vlan')
                else:
                    self.packet = Ether() / self.packet
                    self.set_param(layer='Ether', ptype='ether')

        if self.mode == 'random':
            self.generate_random_packet_list()

        if self.mode == 'plist':
            self.generate_pkt_len_list()

    # set_param()的作用是根据参数前缀将对象属性值设置到数据包的指定协议层中
    def set_param(self, layer, ptype: str):
        for attr, value in self.__dict__.items():
            if attr.startswith(ptype + '_') and value and value != 'random':
                # 处理ipv4 options
                if attr == 'ipv4_options':
                    options_map = {
                            'NOP': IPOption_NOP(),
                            'RR': IPOption_RR(),
                            'LSRR': IPOption_LSRR(),
                            'SSRR': IPOption_SSRR(),
                            'EOL': IPOption_EOL()
                    }
                    option_names = [part.strip() for part in value.split(',') if part.strip()]
                    options = [options_map.get(opt, opt) for opt in option_names if opt in options_map]
                    value = options
                elif type(value) == str and ',' in value:  # 支持生成多个包g
                    value = eval(value)
                elif type(value) == str and value.startswith('int'):
                    value = int(value[3:])
                # 添加对十六进制值的处理
                elif type(value) == str and value.startswith('0x'):
                    value = int(value, 16)
                # 添加对数字字符串的处理
                elif type(value) == str and value.isdigit():
                    value = int(value)
                self.packet[layer].__setattr__(attr.replace(ptype + '_', ''), value)

    def generate_random_packet_list(self):
        for count in range(self.random_count):
            for attr, value in self.__dict__.items():
                if value == 'random':
                    self._set_random_value(attr)
            self.packet_list.append(self.packet)

    def generate_pkt_len_list(self):
        l2_len = len(self.packet)
        for i in self.pkt_len_list.split(','):
            if '-' in i:
                start, end = i.split('-')
                for j in range(int(start), int(end) + 1):
                    # 当有vlan头时，再加上vlan头长度
                    # packet = self.packet/Raw(RandString(size=int(j) -4 -l2_len))
                    if self.random_payload:
                        payload = self.generate_raw_load_packet(str(RandString(size=int(j) - 4 - l2_len)))
                        packet = self.packet / Raw(load=payload)
                    else:
                        # 不需要-4, 既然l2_len已经包括构造的包的所有包头
                        # packet = self.packet / ("a" * (int(j) - 4 - l2_len))
                        packet = self.packet / ("a" * (int(j) - l2_len))
                    self.packet_list.append(packet)
            else:
                if self.random_payload:
                    payload = self.generate_raw_load_packet(str(RandString(size=int(i) - 4 - l2_len)))
                    packet = self.packet / Raw(load=payload)
                else:
                    packet = self.packet / ("a" * (int(i) - 4 - l2_len))
                self.packet_list.append(packet)

    def _set_random_value(self, attr):
        if attr == 'ipv4_src' or attr == 'ipv4_dst':
            self.packet['IP'].__setattr__(attr.replace('ipv4_', ''), RandIP())
        elif attr == 'ipv6_src' or attr == 'ipv6_dst':
            self.packet['IPv6'].__setattr__(attr.replace('ipv6_', ''), random_ipv6(userid=self.userid_ipv6))
        elif attr == 'udp_dport' or attr == 'udp_sport':
            self.packet['UDP'].__setattr__(attr.replace('udp_', ''), RandShort())
        elif attr == 'tcp_sport' or attr == 'tcp_dport':
            self.packet['TCP'].__setattr__(attr.replace('tcp_', ''), RandShort())
        elif attr == 'l2_src' or attr == 'l2_dst':
            self.packet['Ether'].__setattr__(attr.replace('l2_', ''), RandMAC())

    def generate_raw_load_packet(self, data=None):
        if self.crc_check:
            if data is not None:
                data_byte = data.encode('ascii')[2:]
            else:
                data_byte = self.load.encode('ascii')[2:]
            crc_value = (zlib.crc32(data_byte) & 0xFFFF).to_bytes(2, 'big')
            return crc_value + data_byte
        else:
            if data is not None:
                data_byte = data.encode('ascii')
            else:
                data_byte = self.load.encode('ascii')
            return data_byte

    def set_solar_packet(self):
        self.packet = IP() / UDP()
        self.set_param(layer='IP', ptype='ipv4')
        self.set_param(layer='UDP', ptype='udp')
        """solar RDMA header"""
        self.packet = self.packet / BTH(OpCode=d_op_codes[self.rdma_type]) / RDETH()
        self.set_param(layer='BTH', ptype='bth')
        self.set_param(layer='RDETH', ptype='rdeth')
        if self.rdma_type in ops_with_DETH:
            self.packet = self.packet / DETH()
            self.set_param(layer='DETH', ptype='deth')
        if self.rdma_type in ops_with_AETH:
            self.packet = self.packet / AETH()
            self.set_param(layer='AETH', ptype='aeth')
        if self.rdma_type in ops_with_RETH:
            self.packet = self.packet / RETH()
            self.set_param(layer='RETH', ptype='reth')
        if self.rdma_type in ops_with_ImmDt:
            self.packet = self.packet / ImmDt()
            self.set_param(layer='ImmDt', ptype='immdt')
        if self.rdma_type == 'send_only':
            if self.deth_Flags == 1:
                self.packet = self.packet / MDETH()
                self.set_param(layer='MDETH', ptype='mdeth')
            elif self.deth_Flags == 2:
                self.packet = self.packet / DSETH()
                self.set_param(layer='DSETH', ptype='dseth')
        """frag"""
        self.packet = self.packet / FragHead()
        self.set_param(layer='FragHead', ptype='fraghead')
        """data payload"""
        if self.load:
            payload = self.generate_raw_load_packet()
            self.packet = self.packet / Raw(load=payload)
        """PCRC"""
        self.packet = self.packet / PCRC()
        """ICRC"""
        self.packet = self.packet / ICRC()

    def _send_packet(self):
        packet = self.packet
        if self.mode == 'random' or self.mode == 'plist':
            packet = self.packet_list
        if self.send_level == 'l2':
            sendp(packet, iface=self.iface, count=self.count)
        else:
            send(packet, iface=self.iface, count=self.count)

    def send_packet(self):
        self._send_packet()


sp = SendPacket()
parser.parse_args(namespace=sp)
sp.init_packet()
sp.send_packet()
