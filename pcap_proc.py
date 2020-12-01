import pcap, os, sys, pickle, pandas
import os.path as osp
import numpy as np

from time import  time
from datetime import datetime
from enum import Enum
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from socket import inet_ntop, AF_INET
from data_proc import find_data_files


class DnsPacket(KaitaiStruct):
    """(No support for Auth-Name + Add-Name for simplicity)
    """
    class ClassType(Enum):
        in_class = 1
        cs = 2
        ch = 3
        hs = 4

    class TypeType(Enum):
        a = 1
        ns = 2
        md = 3
        mf = 4
        cname = 5
        soe = 6
        mb = 7
        mg = 8
        mr = 9
        null = 10
        wks = 11
        ptr = 12
        hinfo = 13
        minfo = 14
        mx = 15
        txt = 16

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.transaction_id = self._io.read_u2be()
        self.flags = self._root.PacketFlags(self._io, self, self._root)
        self.qdcount = self._io.read_u2be()
        self.ancount = self._io.read_u2be()
        self.nscount = self._io.read_u2be()
        self.arcount = self._io.read_u2be()
        self.queries = [None] * (self.qdcount)
        for i in range(self.qdcount):
            self.queries[i] = self._root.Query(self._io, self, self._root)

        self.answers = [None] * (self.ancount)
        for i in range(self.ancount):
            self.answers[i] = self._root.Answer(self._io, self, self._root)


    class PointerStruct(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.value = self._io.read_u1()

        @property
        def contents(self):
            if hasattr(self, '_m_contents'):
                return self._m_contents if hasattr(self, '_m_contents') else None

            io = self._root._io
            _pos = io.pos()
            io.seek(self.value)
            self._m_contents = self._root.DomainName(io, self, self._root)
            io.seek(_pos)
            return self._m_contents if hasattr(self, '_m_contents') else None


    class Label(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.length = self._io.read_u1()
            if self.is_pointer:
                self.pointer = self._root.PointerStruct(self._io, self, self._root)

            if not (self.is_pointer):
                self.name = (self._io.read_bytes(self.length)).decode(u"ASCII")


        @property
        def is_pointer(self):
            if hasattr(self, '_m_is_pointer'):
                return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None

            self._m_is_pointer = self.length == 192
            return self._m_is_pointer if hasattr(self, '_m_is_pointer') else None


    class Query(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = self._root.DomainName(self._io, self, self._root)
            self.type = self._root.TypeType(self._io.read_u2be())
            self.query_class = self._root.ClassType(self._io.read_u2be())


    class DomainName(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = []
            i = 0
            while True:
                _ = self._root.Label(self._io, self, self._root)
                self.name.append(_)
                if  ((_.length == 0) or (_.length == 192)) :
                    break
                i += 1


    class Address(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ip = [None] * (4)
            for i in range(4):
                self.ip[i] = self._io.read_u1()


    class Answer(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = self._root.DomainName(self._io, self, self._root)
            self.type = self._root.TypeType(self._io.read_u2be())
            self.answer_class = self._root.ClassType(self._io.read_u2be())
            self.ttl = self._io.read_s4be()
            self.rdlength = self._io.read_u2be()
            if self.type == self._root.TypeType.ptr:
                self.ptrdname = self._root.DomainName(self._io, self, self._root)

            if self.type == self._root.TypeType.a:
                self.address = self._root.Address(self._io, self, self._root)


    class PacketFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flag = self._io.read_u2be()

        @property
        def qr(self):
            if hasattr(self, '_m_qr'):
                return self._m_qr if hasattr(self, '_m_qr') else None

            self._m_qr = ((self.flag & 32768) >> 15)
            return self._m_qr if hasattr(self, '_m_qr') else None

        @property
        def ra(self):
            if hasattr(self, '_m_ra'):
                return self._m_ra if hasattr(self, '_m_ra') else None

            self._m_ra = ((self.flag & 128) >> 7)
            return self._m_ra if hasattr(self, '_m_ra') else None

        @property
        def tc(self):
            if hasattr(self, '_m_tc'):
                return self._m_tc if hasattr(self, '_m_tc') else None

            self._m_tc = ((self.flag & 512) >> 9)
            return self._m_tc if hasattr(self, '_m_tc') else None

        @property
        def rcode(self):
            if hasattr(self, '_m_rcode'):
                return self._m_rcode if hasattr(self, '_m_rcode') else None

            self._m_rcode = ((self.flag & 15) >> 0)
            return self._m_rcode if hasattr(self, '_m_rcode') else None

        @property
        def opcode(self):
            if hasattr(self, '_m_opcode'):
                return self._m_opcode if hasattr(self, '_m_opcode') else None

            self._m_opcode = ((self.flag & 30720) >> 11)
            return self._m_opcode if hasattr(self, '_m_opcode') else None

        @property
        def aa(self):
            if hasattr(self, '_m_aa'):
                return self._m_aa if hasattr(self, '_m_aa') else None

            self._m_aa = ((self.flag & 1024) >> 10)
            return self._m_aa if hasattr(self, '_m_aa') else None

        @property
        def z(self):
            if hasattr(self, '_m_z'):
                return self._m_z if hasattr(self, '_m_z') else None

            self._m_z = ((self.flag & 64) >> 6)
            return self._m_z if hasattr(self, '_m_z') else None

        @property
        def rd(self):
            if hasattr(self, '_m_rd'):
                return self._m_rd if hasattr(self, '_m_rd') else None

            self._m_rd = ((self.flag & 256) >> 8)
            return self._m_rd if hasattr(self, '_m_rd') else None

        @property
        def cd(self):
            if hasattr(self, '_m_cd'):
                return self._m_cd if hasattr(self, '_m_cd') else None

            self._m_cd = ((self.flag & 16) >> 4)
            return self._m_cd if hasattr(self, '_m_cd') else None

        @property
        def ad(self):
            if hasattr(self, '_m_ad'):
                return self._m_ad if hasattr(self, '_m_ad') else None

            self._m_ad = ((self.flag & 32) >> 5)
            return self._m_ad if hasattr(self, '_m_ad') else None

class UdpDatagram(KaitaiStruct):
    """UDP is a simple stateless transport layer (AKA OSI layer 4)
    protocol, one of the core Internet protocols. It provides source and
    destination ports, basic checksumming, but provides not guarantees
    of delivery, order of packets, or duplicate delivery.
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.src_port = self._io.read_u2be()
        self.dst_port = self._io.read_u2be()
        self.length = self._io.read_u2be()
        self.checksum = self._io.read_u2be()
        self.body = self._io.read_bytes_full()

class IgmpPacket(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._io.read_bytes(8)
        self.body = self._io.read_bytes_full()

class IcmpPacket(KaitaiStruct):

    class IcmpTypeEnum(Enum):
        echo_reply = 0
        destination_unreachable = 3
        source_quench = 4
        redirect = 5
        echo = 8
        time_exceeded = 11

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._io.read_bytes(8)
        self.body = self._io.read_bytes_full()
        #self._read()

    def _read(self):
        self.icmp_type = self._root.IcmpTypeEnum(self._io.read_u1())
        if self.icmp_type == self._root.IcmpTypeEnum.destination_unreachable:
            self.destination_unreachable = self._root.DestinationUnreachableMsg(self._io, self, self._root)

        if self.icmp_type == self._root.IcmpTypeEnum.time_exceeded:
            self.time_exceeded = self._root.TimeExceededMsg(self._io, self, self._root)

        if  ((self.icmp_type == self._root.IcmpTypeEnum.echo) or (self.icmp_type == self._root.IcmpTypeEnum.echo_reply)) :
            self.echo = self._root.EchoMsg(self._io, self, self._root)


    class DestinationUnreachableMsg(KaitaiStruct):

        class DestinationUnreachableCode(Enum):
            net_unreachable = 0
            host_unreachable = 1
            protocol_unreachable = 2
            port_unreachable = 3
            fragmentation_needed_and_df_set = 4
            source_route_failed = 5
            dst_net_unkown = 6
            sdt_host_unkown = 7
            src_isolated = 8
            net_prohibited_by_admin = 9
            host_prohibited_by_admin = 10
            net_unreachable_for_tos = 11
            host_unreachable_for_tos = 12
            communication_prohibited_by_admin = 13
            host_precedence_violation = 14
            precedence_cuttoff_in_effect = 15
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._root.DestinationUnreachableMsg.DestinationUnreachableCode(self._io.read_u1())
            self.checksum = self._io.read_u2be()


    class TimeExceededMsg(KaitaiStruct):

        class TimeExceededCode(Enum):
            time_to_live_exceeded_in_transit = 0
            fragment_reassembly_time_exceeded = 1
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._root.TimeExceededMsg.TimeExceededCode(self._io.read_u1())
            self.checksum = self._io.read_u2be()


    class EchoMsg(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.code = self._io.ensure_fixed_contents(b"\x00")
            self.checksum = self._io.read_u2be()
            self.identifier = self._io.read_u2be()
            self.seq_num = self._io.read_u2be()
            self.data = self._io.read_bytes_full()

class TcpSegment(KaitaiStruct):
    """TCP is one of the core Internet protocols on transport layer (AKA
    OSI layer 4), providing stateful connections with error checking,
    guarantees of delivery, order of segments and avoidance of duplicate
    delivery.
    """
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.src_port = self._io.read_u2be()
        self.dst_port = self._io.read_u2be()
        self.seq_num = self._io.read_u4be()
        self.ack_num = self._io.read_u4be()
        self.b12 = self._io.read_u1()
        self.b13 = self._io.read_u1()
        self.window_size = self._io.read_u2be()
        self.checksum = self._io.read_u2be()
        self.urgent_pointer = self._io.read_u2be()
        self.body = self._io.read_bytes_full()

class ProtocolBody(KaitaiStruct):
    """Protocol body represents particular payload on transport level (OSI
    layer 4).

    Typically this payload in encapsulated into network level (OSI layer
    3) packet, which includes "protocol number" field that would be used
    to decide what's inside the payload and how to parse it. Thanks to
    IANA's standardization effort, multiple network level use the same
    IDs for these payloads named "protocol numbers".

    This is effectively a "router" type: it expects to get protocol
    number as a parameter, and then invokes relevant type parser based
    on that parameter.

    .. seealso::
       Source - http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    """

    class ProtocolEnum(Enum):
        hopopt = 0
        icmp = 1
        igmp = 2
        ggp = 3
        ipv4 = 4
        st = 5
        tcp = 6
        cbt = 7
        egp = 8
        igp = 9
        bbn_rcc_mon = 10
        nvp_ii = 11
        pup = 12
        argus = 13
        emcon = 14
        xnet = 15
        chaos = 16
        udp = 17
        mux = 18
        dcn_meas = 19
        hmp = 20
        prm = 21
        xns_idp = 22
        trunk_1 = 23
        trunk_2 = 24
        leaf_1 = 25
        leaf_2 = 26
        rdp = 27
        irtp = 28
        iso_tp4 = 29
        netblt = 30
        mfe_nsp = 31
        merit_inp = 32
        dccp = 33
        x_3pc = 34
        idpr = 35
        xtp = 36
        ddp = 37
        idpr_cmtp = 38
        tp_plus_plus = 39
        il = 40
        ipv6 = 41
        sdrp = 42
        ipv6_route = 43
        ipv6_frag = 44
        idrp = 45
        rsvp = 46
        gre = 47
        dsr = 48
        bna = 49
        esp = 50
        ah = 51
        i_nlsp = 52
        swipe = 53
        narp = 54
        mobile = 55
        tlsp = 56
        skip = 57
        ipv6_icmp = 58
        ipv6_nonxt = 59
        ipv6_opts = 60
        any_host_internal_protocol = 61
        cftp = 62
        any_local_network = 63
        sat_expak = 64
        kryptolan = 65
        rvd = 66
        ippc = 67
        any_distributed_file_system = 68
        sat_mon = 69
        visa = 70
        ipcv = 71
        cpnx = 72
        cphb = 73
        wsn = 74
        pvp = 75
        br_sat_mon = 76
        sun_nd = 77
        wb_mon = 78
        wb_expak = 79
        iso_ip = 80
        vmtp = 81
        secure_vmtp = 82
        vines = 83
        ttp_or_iptm = 84
        nsfnet_igp = 85
        dgp = 86
        tcf = 87
        eigrp = 88
        ospfigp = 89
        sprite_rpc = 90
        larp = 91
        mtp = 92
        ax_25 = 93
        ipip = 94
        micp = 95
        scc_sp = 96
        etherip = 97
        encap = 98
        any_private_encryption_scheme = 99
        gmtp = 100
        ifmp = 101
        pnni = 102
        pim = 103
        aris = 104
        scps = 105
        qnx = 106
        a_n = 107
        ipcomp = 108
        snp = 109
        compaq_peer = 110
        ipx_in_ip = 111
        vrrp = 112
        pgm = 113
        any_0_hop = 114
        l2tp = 115
        ddx = 116
        iatp = 117
        stp = 118
        srp = 119
        uti = 120
        smp = 121
        sm = 122
        ptp = 123
        isis_over_ipv4 = 124
        fire = 125
        crtp = 126
        crudp = 127
        sscopmce = 128
        iplt = 129
        sps = 130
        pipe = 131
        sctp = 132
        fc = 133
        rsvp_e2e_ignore = 134
        mobility_header = 135
        udplite = 136
        mpls_in_ip = 137
        manet = 138
        hip = 139
        shim6 = 140
        wesp = 141
        rohc = 142
        reserved_255 = 255

    def __init__(self, protocol_num, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self.protocol_num = protocol_num
        self._read()

    def _read(self):
        _on = self.protocol
        if _on == self._root.ProtocolEnum.tcp:
            self.body = TcpSegment(self._io)
        elif _on == self._root.ProtocolEnum.ipv6_nonxt:
            self.body = self._root.NoNextHeader(self._io, self, self._root)
        elif _on == self._root.ProtocolEnum.icmp:
            self.body = IcmpPacket(self._io)
        elif _on == self._root.ProtocolEnum.udp:
            self.body = UdpDatagram(self._io)
        elif _on == self._root.ProtocolEnum.hopopt:
            self.body = self._root.OptionHopByHop(self._io, self, self._root)
        elif _on == self._root.ProtocolEnum.ipv6:
            self.body = Ipv6Packet(self._io)
        elif _on == self._root.ProtocolEnum.ipv4:
            self.body = Ipv4Packet(self._io)
        elif _on == self._root.ProtocolEnum.igmp:
            self.body = IgmpPacket(self._io)

    class NoNextHeader(KaitaiStruct):
        """Dummy type for IPv6 "no next header" type, which signifies end of headers chain."""

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            pass

    class OptionHopByHop(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.next_header_type = self._io.read_u1()
            self.hdr_ext_len = self._io.read_u1()
            self.body = self._io.read_bytes((self.hdr_ext_len - 1)) if self.hdr_ext_len > 0 else b''
            self.next_header = ProtocolBody(self.next_header_type, self._io)

    @property
    def protocol(self):
        if hasattr(self, '_m_protocol'):
            return self._m_protocol if hasattr(self, '_m_protocol') else None

        self._m_protocol = self._root.ProtocolEnum(self.protocol_num)
        return self._m_protocol if hasattr(self, '_m_protocol') else None

class Ipv4Packet(KaitaiStruct):

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.b1 = self._io.read_u1()
        self.b2 = self._io.read_u1()
        self.total_length = self._io.read_u2be()
        self.identification = self._io.read_u2be()
        self.b67 = self._io.read_u2be()
        self.ttl = self._io.read_u1()
        self.protocol = self._io.read_u1()
        self.header_checksum = self._io.read_u2be()
        self.src_ip_addr = self._io.read_bytes(4)
        self.dst_ip_addr = self._io.read_bytes(4)
        self._raw_options = self._io.read_bytes((self.ihl_bytes - 20))
        io = KaitaiStream(BytesIO(self._raw_options))
        self.options = self._root.Ipv4Options(io, self, self._root)
        self.read_len = self.total_length if self.total_length > 0 else 64
        self._raw_body = self._io.read_bytes(self.read_len - self.ihl_bytes)
        # self._raw_body = self._io.read_bytes((self.total_length - self.ihl_bytes))
        io = KaitaiStream(BytesIO(self._raw_body))
        self.body = ProtocolBody(self.protocol, io)


    class Ipv4Options(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(self._root.Ipv4Option(self._io, self, self._root))
                i += 1


    class Ipv4Option(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.b1 = self._io.read_u1()
            self.len = self._io.read_u1()
            self.body = self._io.read_bytes(((self.len - 2) if self.len > 2 else 0))

        @property
        def copy(self):
            if hasattr(self, '_m_copy'):
                return self._m_copy if hasattr(self, '_m_copy') else None

            self._m_copy = ((self.b1 & 128) >> 7)
            return self._m_copy if hasattr(self, '_m_copy') else None

        @property
        def opt_class(self):
            if hasattr(self, '_m_opt_class'):
                return self._m_opt_class if hasattr(self, '_m_opt_class') else None

            self._m_opt_class = ((self.b1 & 96) >> 5)
            return self._m_opt_class if hasattr(self, '_m_opt_class') else None

        @property
        def number(self):
            if hasattr(self, '_m_number'):
                return self._m_number if hasattr(self, '_m_number') else None

            self._m_number = (self.b1 & 31)
            return self._m_number if hasattr(self, '_m_number') else None


    @property
    def version(self):
        if hasattr(self, '_m_version'):
            return self._m_version if hasattr(self, '_m_version') else None

        self._m_version = ((self.b1 & 240) >> 4)
        return self._m_version if hasattr(self, '_m_version') else None

    @property
    def ihl(self):
        if hasattr(self, '_m_ihl'):
            return self._m_ihl if hasattr(self, '_m_ihl') else None

        self._m_ihl = (self.b1 & 15)
        return self._m_ihl if hasattr(self, '_m_ihl') else None

    @property
    def ihl_bytes(self):
        if hasattr(self, '_m_ihl_bytes'):
            return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None

        self._m_ihl_bytes = (self.ihl * 4)
        return self._m_ihl_bytes if hasattr(self, '_m_ihl_bytes') else None

class Ipv6Packet(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.version = self._io.read_bits_int(4)
        self.traffic_class = self._io.read_bits_int(8)
        self.flow_label = self._io.read_bits_int(20)
        self._io.align_to_byte()
        self.payload_length = self._io.read_u2be()
        self.next_header_type = self._io.read_u1()
        self.hop_limit = self._io.read_u1()
        self.src_ipv6_addr = self._io.read_bytes(16)
        self.dst_ipv6_addr = self._io.read_bytes(16)
        self.next_header = ProtocolBody(self.next_header_type, self._io)
        self.rest = self._io.read_bytes_full()

class EthernetFrame(KaitaiStruct):
    """Ethernet frame is a OSI data link layer (layer 2) protocol data unit
    for Ethernet networks. In practice, many other networks and/or
    in-file dumps adopted the same format for encapsulation purposes.

    .. seealso::
       Source - https://ieeexplore.ieee.org/document/7428776
    """

    class EtherTypeEnum(Enum):
        ipv4 = 2048
        x_75_internet = 2049
        nbs_internet = 2050
        ecma_internet = 2051
        chaosnet = 2052
        x_25_level_3 = 2053
        arp = 2054
        ipv6 = 34525
        lldp = 35020
        unknown = None

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.dst_mac = self._io.read_bytes(6)
        self.src_mac = self._io.read_bytes(6)
        try:
            self.ether_type = self._root.EtherTypeEnum(self._io.read_u2be())
            _on = self.ether_type
        except:
            self.ether_type = self._root.EtherTypeEnum(None)
            _on = None
        if _on == self._root.EtherTypeEnum.ipv4:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = Ipv4Packet(io)
        elif _on == self._root.EtherTypeEnum.ipv6:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = Ipv6Packet(io)
        else:
            self.body = self._io.read_bytes_full()

class PacketPpi(KaitaiStruct):
    """PPI is a standard for link layer packet encapsulation, proposed as
    generic extensible container to store both captured in-band data and
    out-of-band data. Originally it was developed to provide 802.11n
    radio information, but can be used for other purposes as well.

    Sample capture: https://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=Http.cap

    .. seealso::
       PPI header format spec, section 3 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
    """

    class PfhType(Enum):
        radio_802_11_common = 2
        radio_802_11n_mac_ext = 3
        radio_802_11n_mac_phy_ext = 4
        spectrum_map = 5
        process_info = 6
        capture_info = 7

    class Linktype(Enum):
        null_linktype = 0
        ethernet = 1
        ax25 = 3
        ieee802_5 = 6
        arcnet_bsd = 7
        slip = 8
        ppp = 9
        fddi = 10
        ppp_hdlc = 50
        ppp_ether = 51
        atm_rfc1483 = 100
        raw = 101
        c_hdlc = 104
        ieee802_11 = 105
        frelay = 107
        loop = 108
        linux_sll = 113
        ltalk = 114
        pflog = 117
        ieee802_11_prism = 119
        ip_over_fc = 122
        sunatm = 123
        ieee802_11_radiotap = 127
        arcnet_linux = 129
        apple_ip_over_ieee1394 = 138
        mtp2_with_phdr = 139
        mtp2 = 140
        mtp3 = 141
        sccp = 142
        docsis = 143
        linux_irda = 144
        user0 = 147
        user1 = 148
        user2 = 149
        user3 = 150
        user4 = 151
        user5 = 152
        user6 = 153
        user7 = 154
        user8 = 155
        user9 = 156
        user10 = 157
        user11 = 158
        user12 = 159
        user13 = 160
        user14 = 161
        user15 = 162
        ieee802_11_avs = 163
        bacnet_ms_tp = 165
        ppp_pppd = 166
        gprs_llc = 169
        gpf_t = 170
        gpf_f = 171
        linux_lapd = 177
        bluetooth_hci_h4 = 187
        usb_linux = 189
        ppi = 192
        ieee802_15_4 = 195
        sita = 196
        erf = 197
        bluetooth_hci_h4_with_phdr = 201
        ax25_kiss = 202
        lapd = 203
        ppp_with_dir = 204
        c_hdlc_with_dir = 205
        frelay_with_dir = 206
        ipmb_linux = 209
        ieee802_15_4_nonask_phy = 215
        usb_linux_mmapped = 220
        fc_2 = 224
        fc_2_with_frame_delims = 225
        ipnet = 226
        can_socketcan = 227
        ipv4 = 228
        ipv6 = 229
        ieee802_15_4_nofcs = 230
        dbus = 231
        dvb_ci = 235
        mux27010 = 236
        stanag_5066_d_pdu = 237
        nflog = 239
        netanalyzer = 240
        netanalyzer_transparent = 241
        ipoib = 242
        mpeg_2_ts = 243
        ng40 = 244
        nfc_llcp = 245
        infiniband = 247
        sctp = 248
        usbpcap = 249
        rtac_serial = 250
        bluetooth_le_ll = 251
        netlink = 253
        bluetooth_linux_monitor = 254
        bluetooth_bredr_bb = 255
        bluetooth_le_ll_with_phdr = 256
        profibus_dl = 257
        pktap = 258
        epon = 259
        ipmi_hpm_2 = 260
        zwave_r1_r2 = 261
        zwave_r3 = 262
        wattstopper_dlm = 263
        iso_14443 = 264

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = self._root.PacketPpiHeader(self._io, self, self._root)
        self._raw_fields = self._io.read_bytes((self.header.pph_len - 8))
        io = KaitaiStream(BytesIO(self._raw_fields))
        self.fields = self._root.PacketPpiFields(io, self, self._root)
        _on = self.header.pph_dlt
        if _on == self._root.Linktype.ppi:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = PacketPpi(io)
        elif _on == self._root.Linktype.ethernet:
            self._raw_body = self._io.read_bytes_full()
            io = KaitaiStream(BytesIO(self._raw_body))
            self.body = EthernetFrame(io)
        else:
            self.body = self._io.read_bytes_full()


    class PacketPpiFields(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.entries = []
            i = 0
            while not self._io.is_eof():
                self.entries.append(self._root.PacketPpiField(self._io, self, self._root))
                i += 1


    class Radio80211nMacExtBody(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 4.1.3 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.a_mpdu_id = self._io.read_u4le()
            self.num_delimiters = self._io.read_u1()
            self.reserved = self._io.read_bytes(3)


    class MacFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.unused1 = self._io.read_bits_int(1) != 0
            self.aggregate_delimiter = self._io.read_bits_int(1) != 0
            self.more_aggregates = self._io.read_bits_int(1) != 0
            self.aggregate = self._io.read_bits_int(1) != 0
            self.dup_rx = self._io.read_bits_int(1) != 0
            self.rx_short_guard = self._io.read_bits_int(1) != 0
            self.is_ht_40 = self._io.read_bits_int(1) != 0
            self.greenfield = self._io.read_bits_int(1) != 0
            self._io.align_to_byte()
            self.unused2 = self._io.read_bytes(3)


    class PacketPpiHeader(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 3.1 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pph_version = self._io.read_u1()
            self.pph_flags = self._io.read_u1()
            self.pph_len = self._io.read_u2le()
            self.pph_dlt = self._root.Linktype(self._io.read_u4le())


    class Radio80211CommonBody(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 4.1.2 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.tsf_timer = self._io.read_u8le()
            self.flags = self._io.read_u2le()
            self.rate = self._io.read_u2le()
            self.channel_freq = self._io.read_u2le()
            self.channel_flags = self._io.read_u2le()
            self.fhss_hopset = self._io.read_u1()
            self.fhss_pattern = self._io.read_u1()
            self.dbm_antsignal = self._io.read_s1()
            self.dbm_antnoise = self._io.read_s1()

    class PacketPpiField(KaitaiStruct):
        """
        .. seealso::
           PPI header format spec, section 3.1 - https://www.cacetech.com/documents/PPI_Header_format_1.0.1.pdf
        """

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pfh_type = self._root.PfhType(self._io.read_u2le())
            self.pfh_datalen = self._io.read_u2le()
            _on = self.pfh_type
            if _on == self._root.PfhType.radio_802_11_common:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211CommonBody(io, self, self._root)
            elif _on == self._root.PfhType.radio_802_11n_mac_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacExtBody(io, self, self._root)
            elif _on == self._root.PfhType.radio_802_11n_mac_phy_ext:
                self._raw_body = self._io.read_bytes(self.pfh_datalen)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = self._root.Radio80211nMacPhyExtBody(io, self, self._root)
            else:
                self.body = self._io.read_bytes(self.pfh_datalen)


    class Radio80211nMacPhyExtBody(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = self._root.MacFlags(self._io, self, self._root)
            self.a_mpdu_id = self._io.read_u4le()
            self.num_delimiters = self._io.read_u1()
            self.mcs = self._io.read_u1()
            self.num_streams = self._io.read_u1()
            self.rssi_combined = self._io.read_u1()
            self.rssi_ant_ctl = [None] * (4)
            for i in range(4):
                self.rssi_ant_ctl[i] = self._io.read_u1()

            self.rssi_ant_ext = [None] * (4)
            for i in range(4):
                self.rssi_ant_ext[i] = self._io.read_u1()

            self.ext_channel_freq = self._io.read_u2le()
            self.ext_channel_flags = self._root.Radio80211nMacPhyExtBody.ChannelFlags(self._io, self, self._root)
            self.rf_signal_noise = [None] * (4)
            for i in range(4):
                self.rf_signal_noise[i] = self._root.Radio80211nMacPhyExtBody.SignalNoise(self._io, self, self._root)

            self.evm = [None] * (4)
            for i in range(4):
                self.evm[i] = self._io.read_u4le()

        class ChannelFlags(KaitaiStruct):

            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.spectrum_2ghz = self._io.read_bits_int(1) != 0
                self.ofdm = self._io.read_bits_int(1) != 0
                self.cck = self._io.read_bits_int(1) != 0
                self.turbo = self._io.read_bits_int(1) != 0
                self.unused = self._io.read_bits_int(8)
                self.gfsk = self._io.read_bits_int(1) != 0
                self.dyn_cck_ofdm = self._io.read_bits_int(1) != 0
                self.only_passive_scan = self._io.read_bits_int(1) != 0
                self.spectrum_5ghz = self._io.read_bits_int(1) != 0


        class SignalNoise(KaitaiStruct):

            def __init__(self, _io, _parent=None, _root=None):
                self._io = _io
                self._parent = _parent
                self._root = _root if _root else self
                self._read()

            def _read(self):
                self.signal = self._io.read_s1()
                self.noise = self._io.read_s1()

class Pcap(KaitaiStruct):

    class Linktype(Enum):
        null_linktype = 0
        ethernet = 1
        ax25 = 3
        ieee802_5 = 6
        arcnet_bsd = 7
        slip = 8
        ppp = 9
        fddi = 10
        ppp_hdlc = 50
        ppp_ether = 51
        atm_rfc1483 = 100
        raw = 101
        c_hdlc = 104
        ieee802_11 = 105
        frelay = 107
        loop = 108
        linux_sll = 113
        ltalk = 114
        pflog = 117
        ieee802_11_prism = 119
        ip_over_fc = 122
        sunatm = 123
        ieee802_11_radiotap = 127
        arcnet_linux = 129
        apple_ip_over_ieee1394 = 138
        mtp2_with_phdr = 139
        mtp2 = 140
        mtp3 = 141
        sccp = 142
        docsis = 143
        linux_irda = 144
        user0 = 147
        user1 = 148
        user2 = 149
        user3 = 150
        user4 = 151
        user5 = 152
        user6 = 153
        user7 = 154
        user8 = 155
        user9 = 156
        user10 = 157
        user11 = 158
        user12 = 159
        user13 = 160
        user14 = 161
        user15 = 162
        ieee802_11_avs = 163
        bacnet_ms_tp = 165
        ppp_pppd = 166
        gprs_llc = 169
        gpf_t = 170
        gpf_f = 171
        linux_lapd = 177
        bluetooth_hci_h4 = 187
        usb_linux = 189
        ppi = 192
        ieee802_15_4 = 195
        sita = 196
        erf = 197
        bluetooth_hci_h4_with_phdr = 201
        ax25_kiss = 202
        lapd = 203
        ppp_with_dir = 204
        c_hdlc_with_dir = 205
        frelay_with_dir = 206
        ipmb_linux = 209
        ieee802_15_4_nonask_phy = 215
        usb_linux_mmapped = 220
        fc_2 = 224
        fc_2_with_frame_delims = 225
        ipnet = 226
        can_socketcan = 227
        ipv4 = 228
        ipv6 = 229
        ieee802_15_4_nofcs = 230
        dbus = 231
        dvb_ci = 235
        mux27010 = 236
        stanag_5066_d_pdu = 237
        nflog = 239
        netanalyzer = 240
        netanalyzer_transparent = 241
        ipoib = 242
        mpeg_2_ts = 243
        ng40 = 244
        nfc_llcp = 245
        infiniband = 247
        sctp = 248
        usbpcap = 249
        rtac_serial = 250
        bluetooth_le_ll = 251
        netlink = 253
        bluetooth_linux_monitor = 254
        bluetooth_bredr_bb = 255
        bluetooth_le_ll_with_phdr = 256
        profibus_dl = 257
        pktap = 258
        epon = 259
        ipmi_hpm_2 = 260
        zwave_r1_r2 = 261
        zwave_r3 = 262
        wattstopper_dlm = 263
        iso_14443 = 264

    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.hdr = self._root.Header(self._io, self, self._root)
        self.packets = []
        i = 0
        while not self._io.is_eof():
            self.packets.append(self._root.Packet(self._io, self, self._root))
            i += 1

    class Header(KaitaiStruct):

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.magic_number = self._io.ensure_fixed_contents(b"\xD4\xC3\xB2\xA1")
            self.version_major = self._io.read_u2le()
            self.version_minor = self._io.read_u2le()
            self.thiszone = self._io.read_s4le()
            self.sigfigs = self._io.read_u4le()
            self.snaplen = self._io.read_u4le()
            self.network = self._root.Linktype(self._io.read_u4le())

    class Packet(KaitaiStruct):
        """
        .. seealso::
           Source - https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
        """

        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ts_sec = self._io.read_u4le()
            self.ts_usec = self._io.read_u4le()
            self.incl_len = self._io.read_u4le()
            self.orig_len = self._io.read_u4le()
            _on = self._root.hdr.network
            if _on == self._root.Linktype.ppi:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = PacketPpi(io)
            elif _on == self._root.Linktype.ethernet:
                self._raw_body = self._io.read_bytes(self.incl_len)
                io = KaitaiStream(BytesIO(self._raw_body))
                self.body = EthernetFrame(io)
            else:
                self.body = self._io.read_bytes(self.incl_len)

def read_iface(q, iface, port, ip):
    sniffer = pcap.pcap(name=iface, timeout_ms=1)
    while True:
        timestamp, raw = next(sniffer)
        try:
            pkt = EthernetFrame(KaitaiStream(BytesIO(raw)))
            if pkt.ether_type.value == 2048:
                src_ip = inet_ntop(AF_INET, pkt.body.src_ip_addr)
                dst_ip = inet_ntop(AF_INET, pkt.body.dst_ip_addr)
                if src_ip == ip or dst_ip == ip:
                    src_port = 0
                    dst_port = 0
                    flags = 0
                    window = 0
                    proto = pkt.body.protocol
                    if proto in [0, 6, 17]:
                        frame_size = len(raw)
                        read_size = pkt.body.read_len
                        payload_size = len(pkt.body.body.body.body)
                        if proto in [6, 17]:
                            src_port = pkt.body.body.body.src_port
                            dst_port = pkt.body.body.body.dst_port
                            if proto == 6:
                                flags = pkt.body.body.body.b13
                                window = pkt.body.body.body.window_size
                        fields = [
                            timestamp,
                            src_ip,
                            src_port,
                            dst_ip,
                            dst_port,
                            proto,
                            frame_size,
                            14 + read_size - payload_size,
                            decode_tcp_flags_value(flags),
                            window
                        ]
                        if src_port == port or dst_port == port:
                            q.append(fields)
        except Exception as e:
            print(e)

def read_pcap(pcap_file, ports=None):
    sniffer = pcap.pcap(pcap_file)
    count = 0
    pkts = []
    payloads = []
    for timestamp, raw in sniffer:
        count += 1
        try:
            pkt = EthernetFrame(KaitaiStream(BytesIO(raw)))
            if pkt.ether_type.value == 2048:
                src_ip = inet_ntop(AF_INET, pkt.body.src_ip_addr)
                dst_ip = inet_ntop(AF_INET, pkt.body.dst_ip_addr)
                src_port = 0
                dst_port = 0
                flags = 0
                window = 0
                payload = ''
                proto = pkt.body.protocol
                if proto in [0, 6, 17]:
                    frame_size = len(raw)
                    read_size = pkt.body.read_len
                    payload_size = len(pkt.body.body.body.body)
                    if proto in [6, 17]:
                        src_port = pkt.body.body.body.src_port
                        dst_port = pkt.body.body.body.dst_port
                        if proto == 6:
                            flags = pkt.body.body.body.b13
                            window = pkt.body.body.body.window_size
                            payload = pkt.body.body.body.body.decode('ascii','ignore')
                    fields = [
                        timestamp,
                        src_ip,
                        src_port,
                        dst_ip,
                        dst_port,
                        proto,
                        frame_size,
                        14 + read_size - payload_size,
                        decode_tcp_flags_value(flags),
                        window
                    ]
                    if ports is not None:
                        if src_port in ports or dst_port in ports:
                            pkts.append(fields)
                            payloads.append(payload)
                    else:
                        pkts.append(fields)
                        payloads.append(payload)
        except:
            pass
    return pkts, payloads

def decode_tcp_flags_value(value):
    b = '{0:b}'.format(value)[::-1]
    positions = '.'.join([str(i) for i in range(len(b)) if b[i] == '1'])
    return positions

def detailed_flows(flow_ids, pkt_lists, pkt_flags, pkt_directions):

    flow_ids_, pkt_lists_, pkt_flags_, pkt_directions_ = [], [], [], []

    for flow_id, pkt_list, pkt_flag_list, pkt_dirs in zip(flow_ids, pkt_lists, pkt_flags, pkt_directions):
        ack_count = 0
        for i,pkt in enumerate(pkt_list):
            if '4' in str(pkt_flag_list[i]) and '0' not in str(pkt_flag_list[i]) and '1' not in str(pkt_flag_list[i]) and pkt_dirs[i] == -1: # ACK without FIN and SYN from the server to the client
                flow_ids_.append(flow_id)
                pkt_lists_.append(pkt_list[:i+1])
                pkt_flags_.append(pkt_flag_list[:i+1])
                pkt_directions_.append(pkt_dirs[:i+1])
                ack_count += 1
        flow_ids_.append(flow_id)
        pkt_lists_.append(pkt_list)
        pkt_flags_.append(pkt_flag_list)
        pkt_directions_.append(pkt_dirs)

    return flow_ids_, pkt_lists_, pkt_flags_, pkt_directions_

def calculate_features(flow_ids, pkt_lists, pkt_flags, pkt_directions, bulk_thr=1.0, idle_thr=5.0):

    # flow id = src_ip-src_port-dst_ip-dst_port-protocol

    # 0 - timestamp
    # 1 - total size
    # 2 - header size
    # 3 - window size

    features = []

    for flow_id, pkt_list, pkt_flag_list, pkt_dirs in zip(flow_ids, pkt_lists, pkt_flags, pkt_directions):

        # all packets

        pkts = np.array(pkt_list, ndmin=2)
        flags = ''.join([str(pf) for pf in pkt_flag_list])
        dt = np.zeros(len(pkts))
        dt[1:] = pkts[1:, 0] - pkts[:-1, 0]
        idle_idx = np.where(dt > idle_thr)[0]
        activity_start_idx = np.hstack([0, idle_idx])
        activity_end_idx = np.hstack([idle_idx - 1, len(pkts) - 1])

        # forward and backward packets

        fw_pkts = np.array([pkt for pkt, d in zip(pkt_list, pkt_dirs) if d > 0])
        bw_pkts = np.array([pkt for pkt, d in zip(pkt_list, pkt_dirs) if d < 0])

        if len(fw_pkts) >= 2 and len(bw_pkts) >= 1: # forward SYN, backward SYN-ACK, forward ACK

            # forward and backward flags

            fw_flags = ''.join([str(fl) for fl, d in zip(pkt_flag_list, pkt_dirs) if d > 0])
            bw_flags = ''.join([str(fl) for fl, d in zip(pkt_flag_list, pkt_dirs) if d < 0])

            # forward and backward bulks

            if len(fw_pkts) > 1:
                fwt = np.zeros(len(fw_pkts))
                fwt[1:] = fw_pkts[1:, 0] - fw_pkts[:-1, 0]
                fw_blk_idx = np.where(fwt <= bulk_thr)[0]
                fw_bulk = fw_pkts[fw_blk_idx, :]
                fw_blk_dur = np.sum(fwt[fw_blk_idx])
            elif len(fw_pkts) == 1:
                fw_bulk = [fw_pkts[0, :]]
                fw_blk_dur = 0
            else:
                fw_bulk = []
                fw_blk_dur = 0
            fw_bulk = np.array(fw_bulk)

            if len(bw_pkts) > 1:
                bwt = np.zeros(len(bw_pkts))
                bwt[1:] = bw_pkts[1:, 0] - bw_pkts[:-1, 0]
                bw_blk_idx = np.where(bwt <= bulk_thr)[0]
                bw_bulk = bw_pkts[bw_blk_idx, :]
                bw_blk_dur = np.sum(bwt[bw_blk_idx])
            elif len(bw_pkts) == 1:
                bw_bulk = [bw_pkts[0, :]]
                bw_blk_dur = 0
            else:
                bw_bulk = []
                bw_blk_dur = 0
            bw_bulk = np.array(bw_bulk)

            # calculate features

            is_icmp = 1 if flow_id.endswith('0') else 0
            is_tcp = 1 if flow_id.endswith('6') else 0
            is_udp = 1 if flow_id.endswith('17') else 0

            fl_dur = pkts[-1, 0] - pkts[0, 0]
            tot_fw_pk = len(fw_pkts)
            tot_bw_pk = len(bw_pkts)
            tot_l_fw_pkt = np.sum(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0

            fw_pkt_l_max = np.max(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
            fw_pkt_l_min = np.min(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
            fw_pkt_l_avg = np.mean(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0
            fw_pkt_l_std = np.std(fw_pkts[:, 1]) if len(fw_pkts) > 0 else 0

            bw_pkt_l_max = np.max(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
            bw_pkt_l_min = np.min(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
            bw_pkt_l_avg = np.mean(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0
            bw_pkt_l_std = np.std(bw_pkts[:, 1]) if len(bw_pkts) > 0 else 0

            fl_byt_s = np.sum(pkts[:, 1]) / fl_dur if fl_dur > 0 else -1
            fl_pkt_s = len(pkts) / fl_dur if fl_dur > 0 else -1

            fl_iat_avg = np.mean(pkts[1:, 0] - pkts[:-1, 0]) if len(pkts) > 1 else 0
            fl_iat_std = np.std(pkts[1:, 0] - pkts[:-1, 0]) if len(pkts) > 1 else 0
            fl_iat_max = np.max(pkts[1:, 0] - pkts[:-1, 0]) if len(pkts) > 1 else 0
            fl_iat_min = np.min(pkts[1:, 0] - pkts[:-1, 0]) if len(pkts) > 1 else 0

            fw_iat_tot = np.sum(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
            fw_iat_avg = np.mean(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
            fw_iat_std = np.std(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
            fw_iat_max = np.max(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0
            fw_iat_min = np.min(fw_pkts[1:, 0] - fw_pkts[:-1, 0]) if len(fw_pkts) > 1 else 0

            bw_iat_tot = np.sum(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
            bw_iat_avg = np.mean(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
            bw_iat_std = np.std(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
            bw_iat_max = np.max(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0
            bw_iat_min = np.min(bw_pkts[1:, 0] - bw_pkts[:-1, 0]) if len(bw_pkts) > 1 else 0

            fw_psh_flag = fw_flags.count('3') if len(fw_flags) > 0 else 0
            bw_psh_flag = bw_flags.count('3') if len(fw_flags) > 0 else 0
            fw_urg_flag = fw_flags.count('5') if len(bw_flags) > 0 else 0
            bw_urg_flag = bw_flags.count('5') if len(bw_flags) > 0 else 0

            fw_hdr_len = np.sum(fw_pkts[:, 2]) if len(fw_pkts) > 0 else 0
            bw_hdr_len = np.sum(bw_pkts[:, 2]) if len(bw_pkts) > 0 else 0

            if len(fw_pkts) > 0:
                fw_dur = fw_pkts[-1, 0] - fw_pkts[0, 0]
                fw_pkt_s = len(fw_pkts) / fw_dur if fw_dur > 0 else -1
            else:
                fw_pkt_s = 0
            if len(bw_pkts) > 0:
                bw_dur = bw_pkts[-1, 0] - bw_pkts[0, 0]
                bw_pkt_s = len(bw_pkts) / bw_dur if bw_dur > 0 else -1
            else:
                bw_pkt_s = 0

            pkt_len_min = np.min(pkts[:, 1])
            pkt_len_max = np.max(pkts[:, 1])
            pkt_len_avg = np.mean(pkts[:, 1])
            pkt_len_std = np.std(pkts[:, 1])

            fin_cnt = flags.count('0')
            syn_cnt = flags.count('1')
            rst_cnt = flags.count('2')
            psh_cnt = flags.count('3')
            ack_cnt = flags.count('4')
            urg_cnt = flags.count('5')
            cwe_cnt = 0 #flags.count('6')
            ece_cnt = 0 #flags.count('7')

            down_up_ratio = len(bw_pkts) / len(fw_pkts) if len(fw_pkts) > 0 else -1

            fw_byt_blk_avg = np.mean(fw_bulk[:, 1]) if len(fw_bulk) > 0 else 0
            fw_pkt_blk_avg = len(fw_bulk)
            fw_blk_rate_avg = np.sum(fw_bulk[:, 1]) / fw_blk_dur if fw_blk_dur > 0 else -1
            bw_byt_blk_avg = np.mean(bw_bulk[:, 1]) if len(bw_bulk) > 0 else 0
            bw_pkt_blk_avg = len(bw_bulk)
            bw_blk_rate_avg = np.sum(bw_bulk[:, 1]) / bw_blk_dur if bw_blk_dur > 0 else -1

            subfl_fw_pk = len(fw_pkts) / (len(fw_pkts) - len(fw_bulk)) if len(fw_pkts) - len(fw_bulk) > 0 else -1
            subfl_fw_byt = np.sum(fw_pkts[:, 1]) / (len(fw_pkts) - len(fw_bulk)) if len(fw_pkts) - len(fw_bulk) > 0 else -1
            subfl_bw_pk = len(bw_pkts) / (len(bw_pkts) - len(bw_bulk)) if len(bw_pkts) - len(bw_bulk) > 0 else -1
            subfl_bw_byt = np.sum(bw_pkts[:, 1]) / (len(bw_pkts) - len(bw_bulk)) if len(bw_pkts) - len(bw_bulk) > 0 else -1

            fw_win_byt = fw_pkts[0, 3] if len(fw_pkts) > 0 else 0
            bw_win_byt = bw_pkts[0, 3] if len(bw_pkts) > 0 else 0

            fw_act_pkt = len([pkt for pkt in fw_pkts if is_tcp == 1 and pkt[1] > pkt[2]])
            fw_seg_min = np.min(fw_pkts[:, 2]) if len(fw_pkts) > 0 else 0

            atv_avg = np.mean(pkts[activity_end_idx, 0] - pkts[activity_start_idx, 0])
            atv_std = np.std(pkts[activity_end_idx, 0] - pkts[activity_start_idx, 0])
            atv_max = np.max(pkts[activity_end_idx, 0] - pkts[activity_start_idx, 0])
            atv_min = np.min(pkts[activity_end_idx, 0] - pkts[activity_start_idx, 0])

            idl_avg = np.mean(dt[idle_idx]) if len(idle_idx) > 0 else 0
            idl_std = np.std(dt[idle_idx]) if len(idle_idx) > 0 else 0
            idl_max = np.max(dt[idle_idx]) if len(idle_idx) > 0 else 0
            idl_min = np.min(dt[idle_idx]) if len(idle_idx) > 0 else 0

            label = label_flow(flow_id, pkt_list[0][0])

            # append to the feature list

            features.append([
                is_icmp, # 0 -
                is_tcp, # 1 -
                is_udp, # 2 -
                fl_dur, # 3
                tot_fw_pk, # 4
                tot_bw_pk, # 5
                tot_l_fw_pkt, # 6
                fw_pkt_l_max, # 7
                fw_pkt_l_min, # 8
                fw_pkt_l_avg, # 9
                fw_pkt_l_std, # 10
                bw_pkt_l_max, # 11
                bw_pkt_l_min, # 12
                bw_pkt_l_avg, # 13
                bw_pkt_l_std, # 14
                fl_byt_s, # 15
                fl_pkt_s, # 16
                fl_iat_avg, # 17
                fl_iat_std, # 18
                fl_iat_max, # 19
                fl_iat_min, # 20
                fw_iat_tot, # 21
                fw_iat_avg, # 22
                fw_iat_std, # 23
                fw_iat_max, # 24
                fw_iat_min, # 25
                bw_iat_tot, # 26
                bw_iat_avg, # 27
                bw_iat_std, # 28
                bw_iat_max, # 29
                bw_iat_min, # 30
                fw_psh_flag, # 31
                bw_psh_flag, # 32
                fw_urg_flag, # 33 -
                bw_urg_flag, # 34 -
                fw_hdr_len, # 35
                bw_hdr_len, # 36
                fw_pkt_s, # 37
                bw_pkt_s, # 38
                pkt_len_min, # 39
                pkt_len_max, # 40
                pkt_len_avg, # 41
                pkt_len_std, # 42
                fin_cnt, # 43
                syn_cnt, # 44
                rst_cnt, # 45
                psh_cnt, # 46
                ack_cnt, # 47
                urg_cnt, # 48 -
                cwe_cnt, # 49
                ece_cnt, # 50
                down_up_ratio, # 51
                fw_byt_blk_avg, # 52
                fw_pkt_blk_avg, # 53
                fw_blk_rate_avg, # 54
                bw_byt_blk_avg, # 55
                bw_pkt_blk_avg, # 56
                bw_blk_rate_avg, # 57
                subfl_fw_pk, # 58
                subfl_fw_byt, # 59
                subfl_bw_pk, # 60
                subfl_bw_byt, # 61
                fw_win_byt, # 62
                bw_win_byt, # 63
                fw_act_pkt, # 64
                fw_seg_min, # 65 -
                atv_avg, # 66
                atv_std, # 67
                atv_max, # 68
                atv_min, # 69
                idl_avg, # 70
                idl_std, # 71
                idl_max, # 72
                idl_min, # 73
                label
            ])

    return features

def calculate_features_(idx, bulk_thr=1.0, idle_thr=5.0):

    # src_ip-src_port-dst_ip-dst_port-protocol

    # 0 - timestamp
    # 1 - total size
    # 2 - header size
    # 3 - window size

    wcount = 0
    while True:
        flow_ids, pkt_lists, pkt_flags, pkt_directions = flow_q.get()
        n_flows = len(flow_ids)
        n_features = 75
        features = np.zeros((n_flows, n_features))

        pkt_arrays = [np.array(pkt_list, ndmin=2) for pkt_list in pkt_lists]
        flag_lists = [''.join(pkt_flag_list) for pkt_flag_list in pkt_flags]
        dts = [pkt_array[1:, 0] - pkt_array[:-1, 0] for pkt_array in pkt_arrays]
        dts = [np.append(0, dt) for dt in dts]
        idle_ids = [np.where(dt > idle_thr)[0] for dt in dts]
        activity_start_ids = [np.append(0, idle_idx) for idle_idx in idle_ids]
        activity_end_ids = [np.append(idle_idx - 1, len(pkt_list) - 1) for idle_idx, pkt_list in zip(idle_ids, pkt_lists)]

        fw_pkt_lists = [[pkt for pkt, d in zip(pkt_list, pkt_dirs) if d > 0] for pkt_list, pkt_dirs in zip(pkt_lists, pkt_directions)]
        fw_pkt_arrays = [np.array(pkt_list, ndmin=2) for pkt_list in fw_pkt_lists]
        fw_durs = [(pkt_array[-1, 0] - pkt_array[0, 0] if pkt_array.shape[0] > 1 else 0) if pkt_array.size > 0 else -1 for pkt_array in fw_pkt_arrays]
        fw_flag_lists = ['.'.join([fl for fl, d in zip(pkt_flag_list, pkt_dir_list) if d > 0]) for pkt_flag_list, pkt_dir_list in zip(pkt_flags, pkt_directions)]
        fw_dts = [pkt_array[1:, 0] - pkt_array[:-1, 0] if pkt_array.shape[0] > 1 else [] for pkt_array in fw_pkt_arrays]
        fw_dts = [np.append(0, dt) if pkt_array.size > 0 else np.array([]) for dt, pkt_array in zip(fw_dts, fw_pkt_arrays)]
        fw_blk_ids = [np.where(fw_dt <= bulk_thr)[0] for fw_dt in fw_dts]
        fw_blk_lists = [[fw_pkt_list[fw_blk_i] for fw_blk_i in fw_blk_idx] for fw_pkt_list, fw_blk_idx in zip(fw_pkt_lists, fw_blk_ids)]
        fw_blk_arrays = [np.array(fw_blk_list, ndmin=2) for fw_blk_list in fw_blk_lists]
        fw_blk_durs = [np.sum(fw_dt) for fw_dt in fw_dts]

        bw_pkt_lists = [[pkt for pkt, d in zip(pkt_list, pkt_dirs) if d < 0] for pkt_list, pkt_dirs in zip(pkt_lists, pkt_directions)]
        bw_pkt_arrays = [np.array(pkt_list, ndmin=2) for pkt_list in bw_pkt_lists]
        bw_durs = [(pkt_array[-1, 0] - pkt_array[0, 0] if pkt_array.shape[0] > 1 else 0) if pkt_array.size > 0 else -1 for pkt_array in bw_pkt_arrays]
        bw_flag_lists = ['.'.join([fl for fl, d in zip(pkt_flag_list, pkt_dir_list) if d < 0]) for pkt_flag_list, pkt_dir_list in zip(pkt_flags, pkt_directions)]
        bw_dts = [pkt_array[1:, 0] - pkt_array[:-1, 0] if pkt_array.shape[0] > 1 else [] for pkt_array in bw_pkt_arrays]
        bw_dts = [np.append(0, dt) if pkt_array.size > 0 else np.array([]) for dt, pkt_array in zip(bw_dts, bw_pkt_arrays)]
        bw_blk_ids = [np.where(bw_dt <= bulk_thr)[0] for bw_dt in bw_dts]
        bw_blk_lists = [[bw_pkt_list[bw_blk_i] for bw_blk_i in bw_blk_idx] for bw_pkt_list, bw_blk_idx in zip(bw_pkt_lists, bw_blk_ids)]
        bw_blk_arrays = [np.array(bw_blk_list, ndmin=2) for bw_blk_list in bw_blk_lists]
        bw_blk_durs = [np.sum(bw_dt) for bw_dt in bw_dts]

        # calculate features

        is_protos = [np.hstack([1 if flow_id.endswith('0') else 0,
                                1 if flow_id.endswith('6') else 0,
                                1 if flow_id.endswith('17') else 0]) for flow_id in flow_ids]

        fl_durs = [pkt_array[-1, 0] - pkt_array[0, 0] for pkt_array in pkt_arrays]
        tot_fw_pk = [fw_pkt_array.shape[0] if fw_pkt_array.size > 0 else 0 for fw_pkt_array in fw_pkt_arrays]
        tot_bw_pk = [bw_pkt_array.shape[0] if bw_pkt_array.size > 0 else 0 for bw_pkt_array in bw_pkt_arrays]
        tot_l_fw_pkt = [np.sum(fw_pkt_array[:, 1]) if fw_pkt_array.size > 0 else 0 for fw_pkt_array in fw_pkt_arrays]

        fw_pkt_l = [np.hstack([np.max(fw_pkt_array[:, 1]),
                               np.min(fw_pkt_array[:, 1]),
                               np.mean(fw_pkt_array[:, 1]),
                               np.std(fw_pkt_array[:, 1])]) if fw_pkt_array.size > 0 else np.zeros(4) for fw_pkt_array in fw_pkt_arrays]

        bw_pkt_l = [np.hstack([np.max(bw_pkt_array[:, 1]),
                               np.min(bw_pkt_array[:, 1]),
                               np.mean(bw_pkt_array[:, 1]),
                               np.std(bw_pkt_array[:, 1])]) if bw_pkt_array.size > 0 else np.zeros(4) for bw_pkt_array in bw_pkt_arrays]

        fl_s = [np.hstack([np.sum(pkt_array[:, 1]) / fl_dur,
                           pkt_array.shape[0] / fl_dur]) if fl_dur > 0 else -np.ones(2) for pkt_array, fl_dur in zip(pkt_arrays, fl_durs)]

        fl_iat = [np.hstack([np.sum(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.mean(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.std(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.min(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.max(pkt_array[1:, 0] - pkt_array[:-1, 0])]) if pkt_array.shape[0] > 1 else np.zeros(5) for pkt_array in pkt_arrays]

        fw_iat = [np.hstack([np.sum(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.mean(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.std(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.min(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.max(pkt_array[1:, 0] - pkt_array[:-1, 0])]) if pkt_array.shape[0] > 1 else np.zeros(5) for pkt_array in fw_pkt_arrays]

        bw_iat = [np.hstack([np.sum(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.mean(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.std(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.min(pkt_array[1:, 0] - pkt_array[:-1, 0]),
                             np.max(pkt_array[1:, 0] - pkt_array[:-1, 0])]) if pkt_array.shape[0] > 1 else np.zeros(5) for pkt_array in bw_pkt_arrays]

        fw_psh_flags = [np.hstack([fw_flags.count('3'),
                                   fw_flags.count('5')]) if len(fw_flags) > 0 else np.zeros(2) for fw_flags in fw_flag_lists]
        bw_psh_flags = [np.hstack([bw_flags.count('3'),
                                   bw_flags.count('5')]) if len(bw_flags) > 0 else np.zeros(2) for bw_flags in bw_flag_lists]

        fw_hdr_len = [np.sum(fw_pkt_array[:, 2]) if fw_pkt_array.size > 0 else 0 for fw_pkt_array in fw_pkt_arrays]
        bw_hdr_len = [np.sum(bw_pkt_array[:, 2]) if bw_pkt_array.size > 0 else 0 for bw_pkt_array in bw_pkt_arrays]

        fw_pkt_s = [(fw_pkt_array.shape[0] / fw_dur if fw_dur > 0 else -1) if fw_dur >= 0 else 0 for fw_pkt_array, fw_dur in zip(fw_pkt_arrays, fw_durs)]
        bw_pkt_s = [(bw_pkt_array.shape[0] / bw_dur if bw_dur > 0 else -1) if bw_dur >= 0 else 0 for bw_pkt_array, bw_dur in zip(bw_pkt_arrays, bw_durs)]

        pkt_len_min = [np.min(pkt_array[:, 1]) for pkt_array in pkt_arrays]
        pkt_len_max = [np.max(pkt_array[:, 1]) for pkt_array in pkt_arrays]
        pkt_len_avg = [np.mean(pkt_array[:, 1]) for pkt_array in pkt_arrays]
        pkt_len_std = [np.std(pkt_array[:, 1]) for pkt_array in pkt_arrays]

        fin_cnt = [flags.count('0') for flags in flag_lists]
        syn_cnt = [flags.count('1') for flags in flag_lists]
        rst_cnt = [flags.count('2') for flags in flag_lists]
        psh_cnt = [flags.count('3') for flags in flag_lists]
        ack_cnt = [flags.count('4') for flags in flag_lists]
        urg_cnt = [flags.count('5') for flags in flag_lists]
        cwe_cnt = [flags.count('6') for flags in flag_lists]
        ece_cnt = [flags.count('7') for flags in flag_lists]

        down_up_ratio = [len(bw_pkt_list) / len(fw_pkt_list) if len(fw_pkt_list) > 0 else -1 for bw_pkt_list, fw_pkt_list in zip(bw_pkt_lists, fw_pkt_lists)]

        fw_byt_blk_avg = [np.mean(fw_blk_array[:, 1]) if fw_blk_array.size > 0 else 0 for fw_blk_array in fw_blk_arrays]
        fw_pkt_blk_avg = [len(fw_blk_list) for fw_blk_list in fw_blk_lists]
        fw_blk_rate_avg = [np.sum(fw_blk_array[:, 1]) / fw_blk_dur if fw_blk_dur > 0 else -1 for fw_blk_array, fw_blk_dur in zip(fw_blk_arrays, fw_blk_durs)]
        bw_byt_blk_avg = [np.mean(bw_blk_array[:, 1]) if bw_blk_array.size > 0 else 0 for bw_blk_array in bw_blk_arrays]
        bw_pkt_blk_avg = [len(bw_blk_list) for bw_blk_list in bw_blk_lists]
        bw_blk_rate_avg = [np.sum(bw_blk_array[:, 1]) / bw_blk_dur if bw_blk_dur > 0 else -1 for bw_blk_array, bw_blk_dur in zip(bw_blk_arrays, bw_blk_durs)]

        subfl_fw_pk = [len(fw_pkt_list) / (len(fw_pkt_list) - len(fw_blk_list)) if len(fw_pkt_list) - len(fw_blk_list) > 0 else -1 for fw_pkt_list, fw_blk_list in
                       zip(fw_pkt_lists, fw_blk_lists)]
        subfl_fw_byt = [np.sum(fw_pkt_array[:, 1]) / (len(fw_pkt_list) - len(fw_blk_list)) if len(fw_pkt_list) - len(fw_blk_list) > 0 else -1 for
                        fw_pkt_array, fw_pkt_list, fw_blk_list in zip(fw_pkt_arrays, fw_pkt_lists, fw_blk_lists)]
        subfl_bw_pk = [len(bw_pkt_list) / (len(bw_pkt_list) - len(bw_blk_list)) if len(bw_pkt_list) - len(bw_blk_list) > 0 else -1 for bw_pkt_list, bw_blk_list in
                       zip(bw_pkt_lists, bw_blk_lists)]
        subfl_bw_byt = [np.sum(bw_pkt_array[:, 1]) / (len(bw_pkt_list) - len(bw_blk_list)) if len(bw_pkt_list) - len(bw_blk_list) > 0 else -1 for
                        bw_pkt_array, bw_pkt_list, bw_blk_list in zip(bw_pkt_arrays, bw_pkt_lists, bw_blk_lists)]

        fw_win_byt = [fw_pkt_array[0, 3] if fw_pkt_array.size > 0 else 0 for fw_pkt_array in fw_pkt_arrays]
        bw_win_byt = [bw_pkt_array[0, 3] if bw_pkt_array.size > 0 else 0 for bw_pkt_array in bw_pkt_arrays]

        fw_act_pkt = [len([pkt for pkt in fw_pkt_list if is_proto[1] == 1 and pkt[1] > pkt[2]]) for fw_pkt_list, is_proto in zip(fw_pkt_lists, is_protos)]
        fw_seg_min = [np.min(fw_pkt_array[:, 2]) if fw_pkt_array.size > 0 else 0 for fw_pkt_array in fw_pkt_arrays]

        atv = [np.hstack([np.mean(pkt_array[activity_end_idx, 0] - pkt_array[activity_start_idx, 0]),
                          np.std(pkt_array[activity_end_idx, 0] - pkt_array[activity_start_idx, 0]),
                          np.min(pkt_array[activity_end_idx, 0] - pkt_array[activity_start_idx, 0]),
                          np.max(pkt_array[activity_end_idx, 0] - pkt_array[activity_start_idx, 0])])
               for pkt_array, activity_end_idx, activity_start_idx in zip(pkt_arrays, activity_end_ids, activity_start_ids)]

        idl_avg = [np.hstack([np.mean(dt[idle_idx]),
                              np.std(dt[idle_idx]),
                              np.max(dt[idle_idx]),
                              np.min(dt[idle_idx])]) if len(idle_idx) > 0 else 0 for dt, idle_idx in zip(dts, idle_ids)]

        labels = [label_flow(flow_id) for flow_id in flow_ids]

        if 0:
            # append to the feature list

            print(len([
                is_icmp,
                is_tcp,
                is_udp,
                fl_dur,
                tot_fw_pk,
                tot_bw_pk,
                tot_l_fw_pkt,
                fw_pkt_l_max,
                fw_pkt_l_min,
                fw_pkt_l_avg,
                fw_pkt_l_std,
                bw_pkt_l_max,
                bw_pkt_l_min,
                bw_pkt_l_avg,
                bw_pkt_l_std,
                fl_byt_s,
                fl_pkt_s,
                fl_iat_avg,
                fl_iat_std,
                fl_iat_max,
                fl_iat_min,
                fw_iat_tot,
                fw_iat_avg,
                fw_iat_std,
                fw_iat_max,
                fw_iat_min,
                bw_iat_tot,
                bw_iat_avg,
                bw_iat_std,
                bw_iat_max,
                bw_iat_min,
                fw_psh_flag,
                bw_psh_flag,
                fw_urg_flag,
                bw_urg_flag,
                fw_hdr_len,
                bw_hdr_len,
                fw_pkt_s,
                bw_pkt_s,
                pkt_len_min,
                pkt_len_max,
                pkt_len_avg,
                pkt_len_std,
                fin_cnt,
                syn_cnt,
                rst_cnt,
                psh_cnt,
                ack_cnt,
                urg_cnt,
                cwe_cnt,
                ece_cnt,
                down_up_ratio,
                fw_byt_blk_avg,
                fw_pkt_blk_avg,
                fw_blk_rate_avg,
                bw_byt_blk_avg,
                bw_pkt_blk_avg,
                bw_blk_rate_avg,
                subfl_fw_pk,
                subfl_fw_byt,
                subfl_bw_pk,
                subfl_bw_byt,
                fw_win_byt,
                bw_win_byt,
                fw_act_pkt,
                fw_seg_min,
                atv_avg,
                atv_std,
                atv_max,
                atv_min,
                idl_avg,
                idl_std,
                idl_max,
                idl_min,
                label
            ]))

        features_q.put(features)
        wcount += 1

def label_flow(flow_id, ts):
    timestamp = datetime.fromtimestamp(ts)
    date = timestamp.strftime('%d%m')
    if '18.219.211.138' in flow_id and '-6' in flow_id and date == '1502': # DoS-GoldenEye
        label = 1
    elif '18.217.165.70' in flow_id and '-6' in flow_id and date == '1502': # DoS-Slowloris
        label = 2
    elif '18.219.193.20' in flow_id and '-6' in flow_id and date == '1602': # DoS-Hulk
        label = 3
    elif '18.218.115.60' in flow_id and '-6' in flow_id and date in ['2202', '2302']: # BruteForce-Web
        label = 4
    elif '18.219.211.138' in flow_id and '-6' in flow_id and date == '0203':  # Bot
        label = 5
    else:
        label = 0
    return label

def clean_flow_buffer(flow_ids, flow_pkts, flow_pkt_flags, flow_dirs, current_time, idle_thr=5.0, tcp_duration_thr=np.inf):
    flow_ids_new = []
    flow_pkts_new = []
    flow_pkt_flags_new = []
    flow_dirs_new = []
    flow_ids_finished = []
    flow_pkts_finished = []
    flow_pkt_flags_finished = []
    flow_dirs_finished = []
    count_stay = 0
    count_tcp = 0
    count_not_tcp = 0
    count_time = 0
    for fi, fp, ff, fd in zip(flow_ids, flow_pkts, flow_pkt_flags, flow_dirs):
        flags = ''.join([str(f) for f in ff])
        if (fi.endswith('0') or fi.endswith('17')) and current_time - fp[-1][0] > idle_thr:
            count_not_tcp += 1
            flow_ids_finished.append(fi)
            flow_pkts_finished.append(fp)
            flow_pkt_flags_finished.append(ff)
            flow_dirs_finished.append(fd)
        elif fi.endswith('6') and ('0' in flags or '2' in flags) and current_time - fp[-1][0] > idle_thr:
            count_tcp += 1
            flow_ids_finished.append(fi)
            flow_pkts_finished.append(fp)
            flow_pkt_flags_finished.append(ff)
            flow_dirs_finished.append(fd)
        elif current_time - fp[-1][0] > tcp_duration_thr:
            count_time += 1
            flow_ids_finished.append(fi)
            flow_pkts_finished.append(fp)
            flow_pkt_flags_finished.append(ff)
            flow_dirs_finished.append(fd)
        else:
            count_stay += 1
            flow_ids_new.append(fi)
            flow_pkts_new.append(fp)
            flow_pkt_flags_new.append(ff)
            flow_dirs_new.append(fd)
    return flow_ids_new, flow_pkts_new, flow_pkt_flags_new, flow_dirs_new, flow_ids_finished, flow_pkts_finished, flow_pkt_flags_finished, flow_dirs_finished, [count_tcp, count_not_tcp, count_time]

def extract_flows(pkt_file, step=1.0, ports=None):

    p = pandas.read_csv(pkt_file, delimiter=',', skiprows=0, na_filter=False, header=None)
    pkts = p.values

    flow_ids = []
    flows = []
    tracked_flow_ids = []
    tracked_flow_packets = []
    tracked_flow_pkt_flags = []
    tracked_flow_directions = []
    timeline = np.hstack([pkt[0] for pkt in pkts])
    time_min = np.floor(np.min(timeline))

    timestep_idx = 0
    src_ip_idx = 1
    src_port_idx = 2
    dst_ip_idx = 3
    dst_port_idx = 4
    proto_idx = 5
    size_idx = 6
    header_idx = 7
    flag_idx = 8
    window_idx = 9
    id_idx = [src_ip_idx, src_port_idx, dst_ip_idx, dst_port_idx, proto_idx]
    reverse_id_idx = [dst_ip_idx, dst_port_idx, src_ip_idx, src_port_idx, proto_idx]

    t = time_min + step
    counts_total = [0, 0, 0]

    # main loop

    for i, pkt in enumerate(pkts):

        # in case of new time window

        if pkt[0] > t or i == len(pkts) - 1:
            tracked_flow_ids, tracked_flow_packets, tracked_flow_pkt_flags, tracked_flow_directions, finished_flow_ids, finished_flow_packets, finished_flow_pkt_flags, finished_flow_directions, counts = clean_flow_buffer(
                tracked_flow_ids,
                tracked_flow_packets,
                tracked_flow_pkt_flags,
                tracked_flow_directions,
                t
            )
            finished_flow_ids, finished_flow_packets, finished_flow_pkt_flags, finished_flow_directions = detailed_flows(finished_flow_ids, finished_flow_packets, finished_flow_pkt_flags, finished_flow_directions)
            features_finished = calculate_features(finished_flow_ids, finished_flow_packets, finished_flow_pkt_flags, finished_flow_directions)
            flows.extend(features_finished)
            flow_ids.extend(finished_flow_ids)
            features = calculate_features(tracked_flow_ids, tracked_flow_packets, tracked_flow_pkt_flags, tracked_flow_directions)
            flows.extend(features)
            flow_ids.extend(tracked_flow_ids)
            t = int(pkt[0]) + step
            counts_total = [ct + c for ct, c in zip(counts_total, counts)]
            #print('Progress: {0}%, # tracked: {1}, # finished: {2}'.format(100.0*i/len(pkts), len(features), len(features_finished)))

        # otherwise

        if ports is not None and (pkt[src_port_idx] in ports or pkt[dst_port_idx] in ports):
            if pkt[dst_port_idx] in ports:
                id = '-'.join([str(item) for item in [pkt[idx] for idx in id_idx]])
                direction = 1
            elif pkt[src_port_idx] in ports:
                id = '-'.join([str(item) for item in [pkt[idx] for idx in reverse_id_idx]])
                direction = -1
            else:
                id = None
            if id is not None and id not in tracked_flow_ids and '1' in str(pkt[flag_idx]) and '4' not in str(pkt[flag_idx]) and direction == 1: # SYN without ACK
                tracked_flow_ids.append(id)
                tracked_flow_packets.append([np.array([pkt[timestep_idx], pkt[size_idx], pkt[header_idx], pkt[window_idx]])])
                tracked_flow_pkt_flags.append([pkt[flag_idx]])
                tracked_flow_directions.append([direction])
            elif id is not None and id in tracked_flow_ids:
                idx = tracked_flow_ids.index(id)
                tracked_flow_packets[idx].append(np.array([pkt[timestep_idx], pkt[size_idx], pkt[header_idx], pkt[window_idx]]))
                tracked_flow_pkt_flags[idx].append(pkt[flag_idx])
                tracked_flow_directions[idx].append(direction)
    return flows, flow_ids

if __name__ == '__main__':

    # args

    mode = sys.argv[1]
    main_dir = sys.argv[2]
    if len(sys.argv) == 5:
        subnets = sys.argv[3].split(',')
        ports = [int(port) for port in sys.argv[4].split(',')]
    else:
        subnets = None
        ports = None

    # dirs

    if len(mode.split('-')) == 2:
        input_dir = osp.join(main_dir, mode.split('-')[0])
        result_dir = osp.join(main_dir, mode.split('-')[1])
        if not osp.exists(result_dir): os.makedirs(result_dir)
        if mode.split('-')[1] == 'flows':
            flow_stats_file = osp.join(result_dir, 'stats.pkl')
    else:
        print('What?')
        sys.exit(1)

    # dir with input files

    input_subdir_names = []
    input_files = []
    for d in os.listdir(input_dir):
        dd = osp.join(input_dir, d)
        if osp.isdir(dd):
            input_subdir_names.append(d)
            input_files.append(find_data_files(dd))

    # stats

    N = 0
    X_min, X_max, X_mean, X_std = None, None, None, None

    # read inputs one by one

    for input_subdir_name, inputs in zip(input_subdir_names, input_files):
        input_sub_dir = osp.join(input_dir, input_subdir_name)
        if not osp.exists(input_sub_dir): os.makedirs(input_sub_dir)
        result_sub_dir = osp.join(result_dir, input_subdir_name)
        if not osp.exists(result_sub_dir): os.makedirs(result_sub_dir)
        for i,input_file in enumerate(inputs):
            result_file = osp.join(result_sub_dir, osp.basename(input_file))
            if subnets is not None:
                process_file = False
                for subnet in subnets:
                    if subnet in input_file:
                        process_file = True
                        break
            else:
                process_file = True
            if process_file:
                print(i, input_file)
                if mode == 'pcaps-packets':
                    results, _ = read_pcap(input_file, ports=ports)
                elif mode == 'packets-flows':
                    results, flow_ids = extract_flows(input_file, ports=ports)
            else:
                results = []
            if len(results) > 0:
                if mode == 'pcaps-packets':
                    lines = [','.join([str(item) for item in result]) for result in results]
                elif mode == 'packets-flows':
                    lines = ['{0},{1}'.format(flow_id, ','.join([str(item) for item in result])) for result, flow_id in zip(results, flow_ids)]
                with open(result_file, 'w') as f:
                    f.writelines('\n'.join(lines))
                print('{0} {1} have been extracted and saved'.format(len(results), mode.split('-')[1]))

            if mode == 'packets-flows' and len(results) > 0:
                flows = np.array(results)
                idx = np.where(np.all(flows >= 0, axis=1) == True)[0]
                if len(idx) > 0:
                    x_min = np.min(flows[idx, :], axis=0)
                    x_max = np.max(flows[idx, :], axis=0)
                    x_mean = np.mean(flows[idx, :], axis=0)
                    x_std = np.std(flows[idx, :], axis=0)
                    n = flows.shape[0]
                    if X_min is None:
                        X_min = x_min
                    else:
                        X_min = np.min(np.vstack([x_min, X_min]), axis=0)
                    if X_max is None:
                        X_max = x_max
                    else:
                        X_max = np.max(np.vstack([x_max, X_max]), axis=0)
                    if X_mean is None and X_std is None:
                        X_mean = x_mean
                        X_std = x_std
                        N = n
                    else:
                        mu = (N * X_mean + n * x_mean) / (N + n)
                        D = X_mean - mu
                        d = x_mean - mu
                        X_std = np.sqrt((N * (D ** 2 + X_std ** 2) + n * (d ** 2 + x_std ** 2)) / (N + n))
                        N = N + n
                        X_mean = mu

                    # save stats

                    with open(flow_stats_file, 'wb') as f:
                        pickle.dump([N, X_min, X_max, X_mean, X_std], f)