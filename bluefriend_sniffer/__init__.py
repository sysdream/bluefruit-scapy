"""
Adafruit's Bluefriend Sniffer support for Scapy

Author  : Damien "virtualabs" Cauquil
Email   : <d.cauquil@sysdream.com>
Email   : <virtualabs@gmail.com>
Version : 1.0

License : GPL v2 (see LICENSE file)
"""

import socket,struct,array
from scapy.all import *

##########
# Fields #
##########

class XLEShortField(LEShortField):
    def i2repr(self, pkt, x):
        return lhex(self.i2h(pkt, x))

class LEMACField(Field):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "6s")
    def i2m(self, pkt, x):
        if x is None:
            return "\0\0\0\0\0\0"
        return mac2str(x)[::-1]
    def m2i(self, pkt, x):
        return str2mac(x[::-1])
    def any2i(self, pkt, x):
        if type(x) is str and len(x) is 6:
            x = self.m2i(pkt, x)
        return x
    def i2repr(self, pkt, x):
        x = self.i2h(pkt, x)
        if self in conf.resolve:
            x = conf.manufdb._resolve_MAC(x)
        return x
    def randval(self):
        return RandMAC()

################
# Scapy classes
################

class NordicBLE(Packet):
    name="Nordic BLE"
    fields_desc = [
            XByteField('board_id',-1),
            ByteField('proto_version', -1),
            LEShortField('pkt_counter', -1),
            LEShortField('id', -1),
            ShortField('ble_len',-1),
            XByteField('flags', 0),
            ByteField('channel', 0),
            ByteField('rssi', 0),
            ShortField('event_counter', 0),
            LEIntField('timestamp',0),
        ]

    def mysummary(self):
        return self.sprintf("NordicBLE channel=%channel%")


class BLE_LL(Packet):
    name="BLE Link Layer"
    fields_desc = [
        IntEnumField('access', 0, {0xd6be898e: 'broadcast'}),
    ]

class BLE_LL_Adv(Packet):
    name="BLE LL Advertisement"
    fields_desc = [
        BitField('reserved', 0, 1),
        BitField('random_tx_addr', 0, 1),
        BitField('rfu', 0, 2),
        BitField('type', 0, 4),
        ByteField('length', 0),
        LEMACField('adv_address', None),
    ]

    def post_dissect(self, s):
        return s[:-3]

class BLE_LL_Data(Packet):
    name="BLE LL Data"
    fields_desc = [
        BitField('rfu', 0, 3),
        BitField('moar_data', 0, 1),
        BitField('seqn', 0, 1),
        BitField('next_seqn', 0, 1),
        BitField('llid', 0, 2),
        BitField('rfu2', 0, 3),
        BitField('length', 0, 5),
    ]
    def post_dissect(self, s):
        return s[:-3]


##########################################
# ATT packet classes
#
# As defined in the latest scapy release,
# but in case you don't have it, here they
# are.
##########################################

if not hasattr(scapy.layers.bluetooth, 'ATT_Hdr'):
    class ATT_Hdr(Packet):
        name = "ATT header"
        fields_desc = [ XByteField("opcode", None), ]


    class ATT_Error_Response(Packet):
        name = "Error Response"
        fields_desc = [ XByteField("request", 0),
                        LEShortField("handle", 0),
                        XByteField("ecode", 0), ]

    class ATT_Exchange_MTU_Request(Packet):
        name = "Exchange MTU Request"
        fields_desc = [ LEShortField("mtu", 0), ]

    class ATT_Exchange_MTU_Response(Packet):
        name = "Exchange MTU Response"
        fields_desc = [ LEShortField("mtu", 0), ]

    class ATT_Find_Information_Request(Packet):
        name = "Find Information Request"
        fields_desc = [ XLEShortField("start", 0x0000),
                        XLEShortField("end", 0xffff), ]

    class ATT_Find_Information_Response(Packet):
        name = "Find Information Reponse"
        fields_desc = [ XByteField("format", 1),
                        StrField("data", "") ]

    class ATT_Find_By_Type_Value_Request(Packet):
        name = "Find By Type Value Request"
        fields_desc = [ XLEShortField("start", 0x0001),
                        XLEShortField("end", 0xffff),
                        XLEShortField("uuid", None),
                        StrField("data", ""), ]

    class ATT_Find_By_Type_Value_Response(Packet):
        name = "Find By Type Value Response"
        fields_desc = [ StrField("handles", ""), ]

    class ATT_Read_By_Type_Request(Packet):
        name = "Read By Type Request"
        fields_desc = [ XLEShortField("start", 0x0001),
                        XLEShortField("end", 0xffff),
                        XLEShortField("uuid", None), ]

    class ATT_Read_By_Type_Response(Packet):
        name = "Read By Type Response"
        fields_desc = [ FieldLenField("len", None, length_of="data", fmt="B"),
                        StrLenField("data", "", length_from=lambda pkt:pkt.len), ]

    class ATT_Read_Request(Packet):
        name = "Read Request"
        fields_desc = [ XLEShortField("gatt_handle", 0), ]

    class ATT_Read_Response(Packet):
        name = "Read Response"
        fields_desc = [ StrField("value", ""), ]

    class ATT_Read_By_Group_Type_Request(Packet):
        name = "Read By Group Type Request"
        fields_desc = [ XLEShortField("start", 0),
                        XLEShortField("end", 0xffff),
                        XLEShortField("uuid", 0), ]

    class ATT_Read_By_Group_Type_Response(Packet):
        name = "Read By Group Type Response"
        fields_desc = [ XByteField("length", 0),
                        StrField("data", ""), ]

    class ATT_Write_Request(Packet):
        name = "Write Request"
        fields_desc = [ XLEShortField("gatt_handle", 0),
                        StrField("data", ""), ]

    class ATT_Write_Command(Packet):
        name = "Write Request"
        fields_desc = [ XLEShortField("gatt_handle", 0),
                        StrField("data", ""), ]

    class ATT_Write_Response(Packet):
        name = "Write Response"
        fields_desc = [ ]

    class ATT_Handle_Value_Notification(Packet):
        name = "Handle Value Notification"
        fields_desc = [ XLEShortField("handle", 0),
                        StrField("value", ""), ]

############################
# Nordic BLE layer binding
############################

bind_layers( NordicBLE, BLE_LL,)

############################
# BLE/ATT layer bindings
############################

bind_layers( BLE_LL,        BLE_LL_Adv,        access=0xd6be898e)
bind_layers( BLE_LL,        BLE_LL_Data,)
bind_layers( BLE_LL_Data,   L2CAP_Hdr,         llid=2)
bind_layers( L2CAP_Hdr,     ATT_Hdr,           cid=4)
bind_layers( ATT_Hdr,       ATT_Error_Response, opcode=0x1)
bind_layers( ATT_Hdr,       ATT_Exchange_MTU_Request, opcode=0x2)
bind_layers( ATT_Hdr,       ATT_Exchange_MTU_Response, opcode=0x3)
bind_layers( ATT_Hdr,       ATT_Find_Information_Request, opcode=0x4)
bind_layers( ATT_Hdr,       ATT_Find_Information_Response, opcode=0x5)
bind_layers( ATT_Hdr,       ATT_Find_By_Type_Value_Request, opcode=0x6)
bind_layers( ATT_Hdr,       ATT_Find_By_Type_Value_Response, opcode=0x7)
bind_layers( ATT_Hdr,       ATT_Read_By_Type_Request, opcode=0x8)
bind_layers( ATT_Hdr,       ATT_Read_By_Type_Response, opcode=0x9)
bind_layers( ATT_Hdr,       ATT_Read_Request, opcode=0xa)
bind_layers( ATT_Hdr,       ATT_Read_Response, opcode=0xb)
bind_layers( ATT_Hdr,       ATT_Read_By_Group_Type_Request, opcode=0x10)
bind_layers( ATT_Hdr,       ATT_Read_By_Group_Type_Response, opcode=0x11)
bind_layers( ATT_Hdr,       ATT_Write_Request, opcode=0x12)
bind_layers( ATT_Hdr,       ATT_Write_Response, opcode=0x13)
bind_layers( ATT_Hdr,       ATT_Write_Command, opcode=0x52)
bind_layers( ATT_Hdr,       ATT_Handle_Value_Notification, opcode=0x1b)

# Bluefriend sniffer uses DLT id 157 for Nordic BLE packets
conf.l2types.register(157, NordicBLE)
