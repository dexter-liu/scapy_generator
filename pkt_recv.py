import argparse

from scapy.sendrecv import sniff

from util.layers import Ether, BTH
from util.layers import d_op_codes_types


class ArgsParser:
    @staticmethod
    def parse_args():
        arg_parser = argparse.ArgumentParser(description='recv packets')
        arg_parser.add_argument('-i', '--iface', type=str)
        arg_parser.add_argument('-c', '--count', type=int, default=1)
        arg_parser.add_argument('-t', '--timeout', type=int, default=5)
        return vars(arg_parser.parse_args())


parser = ArgsParser()
args = parser.parse_args()
ps = sniff(iface=args['iface'], count=args['count'], timeout=args['timeout'])

for p in ps:
    p = Ether(bytes(p))
    p.show()
    if BTH in p:
        print('-' * 20)
        print(f'RDMA OP:{d_op_codes_types[p[BTH].OpCode]}')
    print('-' * 80)
