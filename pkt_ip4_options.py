import random
from scapy.layers.inet import IP, IPOption_NOP, IPOption_LSRR, IPOption_RR, IPOption_SSRR, IPOption_EOL
from scapy.layers.l2 import Dot1Q, ARP, Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment, IPv6ExtHdrRouting
from scapy.all import send, sendp, srp, sr, sr1, srp1, Raw
from scapy.contrib.mac_control import MACControl, MACControlPause, MACControlClassBasedFlowControl


def test_arp():
    arp_pkt = ARP(op=1, hwsrc="00:00:00:00:00:00")
    print(arp_pkt.show2())

# 构造带ipv4选项的packet

# s = "IPOption_NOP()"
# s = eval(s)
# pkt = IP(options=s)
# print(pkt.show())


# def extract_parts(s):
#     return [part.strip() for part in s.split(',') if part.strip()]

# # 测试
# print(extract_parts("NOP, EOL"))  # 输出: ['NOP', 'EOL']
# print(extract_parts("EOL"))       # 输出: ['EOL']

pkt = IP(src="192.168.16.1", dst="192.168.16.2", flags="MF", frag=0)  # 第一个分片

def test_ipv6_ext():
    ipv6_pkt = IPv6(src="2002::2", dst="2002::1")
    # 添加Hop-by-Hop扩展头
    hbh_hdr = IPv6ExtHdrHopByHop()
    ipv6_pkt = ipv6_pkt / hbh_hdr

    # 添加Destination Options扩展头
    dest_hdr = IPv6ExtHdrDestOpt()
    ipv6_pkt_2 = ipv6_pkt / dest_hdr

def test_pfc_packet():
    pfc = MACControlClassBasedFlowControl()
    pfc_pkt = Ether(src='10:70:fd:91:c2:ba', dst=MACControl.DEFAULT_DST_MAC) / pfc
    # pfc_pkt.show2()
    # print(bytes(pfc_pkt[Ether])[14:28].hex())
    # print(bytes(pfc_pkt[MACControlClassBasedFlowControl])[:14].hex())

    pause = MACControlPause()
    pause_pkt = Ether(src='10:70:fd:91:c2:ba', dst=MACControl.DEFAULT_DST_MAC) / pause
    pause_pkt.show2()
    print(bytes(pause_pkt[Ether])[14:28].hex())
    print(bytes(pause_pkt[MACControlPause])[:14].hex())


def generate_mac_addresses(base_mac, mask: str):
    """
    根据基准MAC地址和掩码生成匹配和不匹配的MAC地址
    :param base_mac: 基准MAC地址 (如 '00:11:22:33:44:55' 或 '0x001122334455')
    :param mask: 掩码 (如 '0x800000000000')
    Returns:
        dict: {'match_mac': matching_mac, 'non_match_mac': non_matching_mac}
    """
    # 将MAC地址转换为整数
    if isinstance(base_mac, str) and (':' in base_mac or '：' in base_mac):
        # 处理格式如 '00:11:22:33:44:55'
        mac_str = base_mac.replace('：', ':')  # 统一转换为英文冒号
        base_int = int(mac_str.replace(':', ''), 16)
    elif isinstance(base_mac, str) and base_mac.startswith('0x'):
        # 处理格式如 '0x001122334455'
        base_int = int(base_mac, 16)
    else:
        # 无法处理的格式
        raise ValueError(f"Unsupported MAC address format: {base_mac}")

    # 将掩码转换为整数
    mask_int = int(mask, 16)

    # 生成匹配的MAC地址：掩码为1的位必须匹配，掩码为0的位可以任意
    random_part = random.randint(0, 0xFFFFFFFFFFFF)
    matching_mac_int = (base_int & mask_int) | (random_part & ~mask_int)

    # 生成不匹配的MAC地址：修改掩码为1的任意一位
    # 找到掩码中最左边的1位
    if mask_int > 0:
        # 获取掩码中最低位的1
        mask_bit = mask_int & (-mask_int)
        # 翻转该位
        non_matching_mac_int = base_int ^ mask_bit
    else:
        # 如果掩码全为0，随机翻转一位
        non_matching_mac_int = base_int ^ 1

    # 转换回MAC地址格式
    def int_to_mac(mac_int):
        mac_hex = f"{mac_int:012x}"
        return ':'.join([mac_hex[i:i + 2] for i in range(0, 12, 2)])

    return {
        'match_mac': int_to_mac(matching_mac_int),
        'non_match_mac': int_to_mac(non_matching_mac_int),
    }


if __name__ == '__main__':
    # result = generate_mac_addresses('08:c0:eb:20:da:f6', '0x000000000001')
    # print(result['match_mac'], result['non_match_mac'])
    test_arp()

