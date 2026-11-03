from typing import Type

from scapy.fields import BitField
from scapy.layers.inet import UDP, Ether
from scapy.packet import Packet, Raw, bind_layers

Ether = Ether


class BTH(Packet):
    name = 'BTH'
    fields_desc = [
        BitField('OpCode', 0, 8),
        BitField('SE', 0, 1),
        BitField('Res0', 0, 15),
        BitField('version', 0, 8),

        BitField('A', 0, 1),
        BitField('Res1', 0, 7),
        BitField('DestinationQP', 0, 24),

        BitField('PSN', 0, 32),
    ]


class RDETH(Packet):
    name = 'RDETH'
    fields_desc = [
        BitField('T', 0, 2),  # todo:??
        BitField('C', 0, 1),
        BitField('S', 0, 1),
        BitField('E', 0, 1),
        BitField('I', 0, 1),
        BitField('R', 0, 1),
        BitField('P', 0, 1),
        BitField('SegPSN', 0, 8),
        BitField('iPSN', 0, 16),

        BitField('MSN', 0, 32),
        BitField('SRC_C_ID', 0, 32),
        BitField('DST_C_ID', 0, 32),
        BitField('TimestampValue', 0, 32),
        BitField('TimestampEcho', 0, 32),
    ]

    def guess_payload_class(self, payload):  # type: (bytes) -> Type[Packet]
        payload_class = {
            0b01000000: DETH,
            0b01000001: DETH,
            0b01000010: DETH,
            0b01000011: DETH,
            0b01000100: DETH,
            0b01000101: DETH,
            0b01000110: DETH,
            0b01000111: DETH,
            0b01001000: DETH,
            0b01001001: DETH,
            0b01001010: DETH,
            0b01001011: DETH,
            0b01001100: DETH,
            0b01001101: AETH,
            0b01001110: FragHead,
            0b01001111: AETH,
            0b01010000: AETH,
            0b01010001: AETH,
            0b01011000: FragHead,
            0b01011001: AETH,
            0b01011010: FragHead,
            0b01011011: AETH,
            0b01011100: FragHead,
            0b01011101: FragHead,
            0b01101100: FragHead,
            0b01101101: FragHead,
        }
        return payload_class[self.underlayer.OpCode]


class DETH(Packet):
    name = 'DETH'
    fields_desc = [
        BitField('Flags', 0, 8),
        BitField('Res', 0, 32),
        BitField('SourceQP', 0, 24),
    ]

    def guess_payload_class(self, payload):  # type: (bytes) -> Type[Packet]
        payload_class = {
            0b01000000: FragHead,
            0b01000001: FragHead,
            0b01000010: FragHead,
            0b01000011: ImmDt,
            # 0b01000100: FragHead,
            0b01000101: ImmDt,
            0b01000110: RETH,
            0b01000111: RETH,
            0b01001000: RETH,
            0b01001001: RETH,
            0b01001010: RETH,
            0b01001011: RETH,
            0b01001100: RETH,
        }

        opcode = self.underlayer.underlayer.OpCode
        if opcode in payload_class:
            return payload_class[opcode]
        elif self.Flags == 0x1:
            return MDETH
        elif self.Flags == 0x2:
            return DSETH
        else:
            return FragHead


class MDETH(Packet):
    name = 'MDETH'
    fields_desc = [
        BitField('Res', 0, 32),
        BitField('DMAKey', 0, 64),
        BitField('DMALength', 0, 32)
    ]


class DSETH(Packet):
    name = 'DSETH'
    fields_desc = [
        BitField('offset', 0, 16),
        BitField('Res', 0, 16),
    ]


class RETH(Packet):
    name = 'RETH'
    fields_desc = [
        BitField('VirtualAddress', 0, 64),

        BitField('R_Key', 0, 32),

        BitField('DmaLength', 0, 32),
    ]


class AETH(Packet):
    name = 'AETH'
    fields_desc = [
        BitField('syndrome', 0, 8),
        BitField('MSN', 0, 24)
    ]


class ImmDt(Packet):
    name = 'ImmDT'
    fields_desc = [
        BitField('ImmediateData', 0, 32)
    ]


class INTProbeHeader(Packet):
    name = 'INTProbeHeader'
    fields_desc = [
        BitField('ProbeMarker1', 0, 32),

        BitField('ProbeMarker2', 0, 32),

        BitField('version', 0, 8),
        BitField('MessageType', 0, 8),
        BitField('Flags', 0, 16),

        BitField('TelemetryRequestVector', 0, 32),

        BitField('HopLimit', 0, 8),
        BitField('HopCount', 0, 8),
        BitField('MustBeZero', 0, 16),

        BitField('MaximumLength', 0, 16),
        BitField('CurrentLength', 0, 16),

        BitField('SenderHandle', 0, 16),
        BitField('SequenceNumber', 0, 16),

    ]


class INTMetaDataHeader(Packet):
    name = 'INTMetaDataHeader'
    fields_desc = [
        BitField('DeviceId', 0, 32),

        BitField('TID', 0, 3),  # todo:??
        BitField('congestion', 0, 5),  # todo:??
        BitField('Drop', 0, 8),
        BitField('TTL', 0, 8),
        BitField('QueueId', 0, 8),

        BitField('RxTimestampSecUpper', 0, 32),

        BitField('RxTimestampSec', 0, 16),
        BitField('RxTimestampNanoUpper', 0, 16),

        BitField('RxTimestampNano', 0, 16),
        BitField('TxTimestampNanoUpper', 0, 16),

        BitField('TxTimestampNano', 0, 16),
        BitField('EgressPortUtilization', 0, 16),

        BitField('SrcSysPort', 0, 16),
        BitField('DstSysPort', 0, 16),

        BitField('PortDropByte', 0, 32),
    ]


class FragHead(Packet):
    name = 'FragHead'
    fields_desc = [
        BitField('magic', 0, 32),
        BitField('offset', 0, 32),
        BitField('msn', 0, 32),

        BitField('flag', 0, 16),
        BitField('iPSN', 0, 16),
    ]


class PCRC(Packet):
    name = 'PCRC'
    fields_desc = [
        BitField('PCRC', 0, 8)
    ]


class ICRC(Packet):
    name = 'ICRC'
    fields_desc = [
        BitField('ICRC', 0, 8)
    ]


# INT
# bind_layers(UDP, INTProbeHeader)
bind_layers(INTProbeHeader, INTMetaDataHeader)
bind_layers(INTMetaDataHeader, INTMetaDataHeader)

for dst_port in range(61300, 61399):
    bind_layers(UDP, BTH, dport=dst_port)  # todo：范围表述
bind_layers(BTH, RDETH)
bind_layers(RDETH, DETH)
bind_layers(RDETH, AETH)

bind_layers(DETH, ImmDt)
bind_layers(DETH, MDETH, Flags='0x1')
bind_layers(DETH, DSETH, Flags='0x2')
bind_layers(DETH, RETH)
bind_layers(RETH, ImmDt)

bind_layers(DETH, FragHead)
bind_layers(ImmDt, FragHead)
bind_layers(MDETH, FragHead)
bind_layers(DSETH, FragHead)
bind_layers(RETH, FragHead)
bind_layers(AETH, FragHead)
bind_layers(RDETH, FragHead)

bind_layers(FragHead, Raw)
bind_layers(Raw, PCRC)
bind_layers(PCRC, ICRC)

ops_with_RDETH = ['send_first', 'send_middle', 'send_last', 'send_last_with_immediate', 'send_only',
                  'send_only_with_immediate', 'rdma_write_first', 'rdma_write_middle', 'rdma_write_last',
                  'rdma_write_last_with_immediate', 'rdma_write_only', 'rdma_write_only_with_immediate',
                  'rdma_read_request', 'rdma_read_response_first', 'rdma_read_response_middle',
                  'rdma_read_response_last', 'rdma_read_response_only', 'acknowledge', 'connect_request',
                  'connect_acknowledge', 'disconnect_request', 'disconnect_acknowledge', 'detection_request',
                  'detection_response', 'tpb_request', 'tpb_response']
ops_with_DETH = ['send_first', 'send_middle', 'send_last', 'send_last_with_immediate', 'send_only',
                 'send_only_with_immediate', 'rdma_write_first', 'rdma_write_middle', 'rdma_write_last',
                 'rdma_write_last_with_immediate', 'rdma_write_only', 'rdma_write_only_with_immediate',
                 'rdma_read_request']
ops_with_AETH = ['rdma_read_response_first', 'rdma_read_response_last', 'rdma_read_response_only', 'acknowledge',
                 'connect_acknowledge', 'disconnect_acknowledge']
ops_with_RETH = ['rdma_write_first', 'rdma_write_middle', 'rdma_write_last',
                 'rdma_write_last_with_immediate', 'rdma_write_only', 'rdma_write_only_with_immediate',
                 'rdma_read_request']
ops_with_ImmDt = ['send_last_with_immediate', 'send_only_with_immediate', 'rdma_write_last_with_immediate',
                  'rdma_write_only_with_immediate']

d_op_codes = {
    'send_first': 0b01000000,
    'send_middle': 0b01000001,
    'send_last': 0b01000010,
    'send_last_with_immediate': 0b01000011,
    'send_only': 0b01000100,
    'send_only_with_immediate': 0b01000101,
    'rdma_write_first': 0b01000110,
    'rdma_write_middle': 0b01000111,
    'rdma_write_last': 0b01001000,
    'rdma_write_last_with_immediate': 0b01001001,
    'rdma_write_only': 0b01001010,
    'rdma_write_only_with_immediate': 0b01001011,
    'rdma_read_request': 0b01001100,
    'rdma_read_response_first': 0b01001101,
    'rdma_read_response_middle': 0b01001110,
    'rdma_read_response_last': 0b01001111,
    'rdma_read_response_only': 0b01010000,
    'acknowledge': 0b01010001,
    'connect_request': 0b01011000,
    'connect_acknowledge': 0b01011001,
    'disconnect_request': 0b01011010,
    'disconnect_acknowledge': 0b01011011,
    'detection_request': 0b01011100,
    'detection_response': 0b01011101,
    'tpb_request': 0b01101100,
    'tpb_response': 0b01101101,
}

d_op_codes_types = {opcode: op_types for op_types, opcode in d_op_codes.items()}
