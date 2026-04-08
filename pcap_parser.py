"""
pcap_parser.py
--------------
Parses a .pcap file (given as a CLI argument) and stores each packet
in a strongly-typed object.  One class is defined per protocol layer;
a PacketRecord wraps all layers found in a single captured frame.

Usage:
    python pcap_parser.py <file.pcap>

Dependencies:
    pip install scapy
"""

import sys
import argparse
from dataclasses import dataclass, field
from typing import Optional
from scapy.all import rdpcap, Packet as ScapyPacket
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS


# ---------------------------------------------------------------------------
# Layer-level classes  (one per protocol)
# ---------------------------------------------------------------------------

@dataclass
class EthernetFrame:
    """IEEE 802.3 Ethernet II header fields."""
    dst     : str           # Destination MAC address
    src     : str           # Source MAC address
    type    : int           # EtherType (e.g. 0x0800 = IPv4, 0x0806 = ARP)
    type_hex: str           # EtherType as '0x....' string for readability

# end class EthernetFrame


@dataclass
class ARPPacket:
    """ARP header fields (RFC 826)."""
    hwtype  : int   # Hardware type (1 = Ethernet)
    ptype   : int   # Protocol type (0x0800 = IPv4)
    hwlen   : int   # Hardware address length (6 for MAC)
    plen    : int   # Protocol address length (4 for IPv4)
    op      : int   # Operation: 1 = request, 2 = reply
    hwsrc   : str   # Sender hardware (MAC) address
    psrc    : str   # Sender protocol (IP) address
    hwdst   : str   # Target hardware (MAC) address
    pdst    : str   # Target protocol (IP) address

# end class ARPPacket


@dataclass
class IPv4Packet:
    """IPv4 header fields (RFC 791)."""
    version : int           # IP version (always 4)
    ihl     : int           # Internet header length (in 32-bit words)
    tos     : int           # Type of service / DSCP+ECN byte
    len     : int           # Total length (header + data) in bytes
    id      : int           # Identification field
    flags   : int           # Fragmentation flags
    frag    : int           # Fragment offset
    ttl     : int           # Time to live
    proto   : int           # Protocol number of the encapsulated payload
    chksum  : int           # Header checksum
    src     : str           # Source IP address
    dst     : str           # Destination IP address

# end class IPv4Packet


@dataclass
class IPv6Packet:
    """IPv6 header fields (RFC 8200)."""
    version : int   # IP version (always 6)
    tc      : int   # Traffic class (DSCP + ECN)
    fl      : int   # Flow label
    plen    : int   # Payload length in bytes
    nh      : int   # Next header protocol number
    hlim    : int   # Hop limit (analogous to IPv4 TTL)
    src     : str   # Source IPv6 address
    dst     : str   # Destination IPv6 address

# end class IPv6Packet


@dataclass
class TCPSegment:
    """TCP header fields (RFC 9293)."""
    sport   : int   # Source port
    dport   : int   # Destination port
    seq     : int   # Sequence number
    ack     : int   # Acknowledgement number
    dataofs : int   # Data offset (header length in 32-bit words)
    reserved: int   # Reserved bits
    flags   : int   # Control bits (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
    window  : int   # Receive window size
    chksum  : int   # Checksum
    urgptr  : int   # Urgent pointer
    payload : bytes # TCP payload bytes

# end class TCPSegment


@dataclass
class UDPDatagram:
    """UDP header fields (RFC 768)."""
    sport   : int   # Source port
    dport   : int   # Destination port
    len     : int   # Length of UDP header + data in bytes
    chksum  : int   # Checksum
    payload : bytes # UDP payload bytes

# end class UDPDatagram


@dataclass
class ICMPMessage:
    """ICMP (v4) header fields (RFC 792)."""
    type    : int   # ICMP message type  (e.g. 8 = echo request, 0 = echo reply)
    code    : int   # Sub-type code
    chksum  : int   # Checksum
    id      : int   # Identifier (used in echo request/reply)
    seq     : int   # Sequence number (used in echo request/reply)
    payload : bytes # ICMP payload bytes

# end class ICMPMessage


@dataclass
class DNSMessage:
    """DNS message fields (RFC 1035).  Only top-level header fields are stored;
    individual RR parsing is delegated to scapy's repr for brevity."""
    id      : int           # Transaction ID
    qr      : int           # 0 = query, 1 = response
    opcode  : int           # Query type (0 = standard query)
    aa      : int           # Authoritative answer flag
    tc      : int           # Truncation flag
    rd      : int           # Recursion desired flag
    ra      : int           # Recursion available flag
    z       : int           # Reserved (must be 0)
    rcode   : int           # Response code (0 = no error)
    qdcount : int           # Number of questions
    ancount : int           # Number of answer RRs
    nscount : int           # Number of authority RRs
    arcount : int           # Number of additional RRs
    summary : str           # Human-readable scapy summary of the full DNS message

# end class DNSMessage


@dataclass
class RawPayload:
    """Fallback for any layer that does not match the known protocols above."""
    proto_name : str    # Scapy layer class name
    raw_bytes  : bytes  # Raw bytes of that layer

# end class RawPayload


# ---------------------------------------------------------------------------
# Top-level container that represents one captured frame
# ---------------------------------------------------------------------------

@dataclass
class PacketRecord:
    """Represents a single captured packet with all its decoded layers."""
    index      : int                         # 1-based position in the capture file
    timestamp  : float                       # Capture timestamp (Unix epoch, µs resolution)
    wire_len   : int                         # Original length on the wire (bytes)
    cap_len    : int                         # Captured length stored in the pcap (bytes)
    ethernet   : Optional[EthernetFrame] = None
    arp        : Optional[ARPPacket]     = None
    ipv4       : Optional[IPv4Packet]    = None
    ipv6       : Optional[IPv6Packet]    = None
    tcp        : Optional[TCPSegment]    = None
    udp        : Optional[UDPDatagram]   = None
    icmp       : Optional[ICMPMessage]   = None
    dns        : Optional[DNSMessage]    = None
    unknowns   : list[RawPayload]        = field(default_factory = list)  # Any unrecognised layers

# end class PacketRecord


# ---------------------------------------------------------------------------
# Parsing helpers  (one per layer)
# ---------------------------------------------------------------------------

def _parse_ethernet(layer: ScapyPacket) -> EthernetFrame:
    return EthernetFrame(
        dst      = layer.dst,
        src      = layer.src,
        type     = layer.type,
        type_hex = hex(layer.type),
    )
# end def _parse_ethernet


def _parse_arp(layer: ScapyPacket) -> ARPPacket:
    return ARPPacket(
        hwtype = layer.hwtype,
        ptype  = layer.ptype,
        hwlen  = layer.hwlen,
        plen   = layer.plen,
        op     = layer.op,
        hwsrc  = layer.hwsrc,
        psrc   = layer.psrc,
        hwdst  = layer.hwdst,
        pdst   = layer.pdst,
    )
# end def _parse_arp


def _parse_ipv4(layer: ScapyPacket) -> IPv4Packet:
    return IPv4Packet(
        version = layer.version,
        ihl     = layer.ihl,
        tos     = layer.tos,
        len     = layer.len,
        id      = layer.id,
        flags   = int(layer.flags),
        frag    = layer.frag,
        ttl     = layer.ttl,
        proto   = layer.proto,
        chksum  = layer.chksum if layer.chksum is not None else 0,
        src     = layer.src,
        dst     = layer.dst,
    )
# end def _parse_ipv4


def _parse_ipv6(layer: ScapyPacket) -> IPv6Packet:
    return IPv6Packet(
        version = layer.version,
        tc      = layer.tc,
        fl      = layer.fl,
        plen    = layer.plen,
        nh      = layer.nh,
        hlim    = layer.hlim,
        src     = layer.src,
        dst     = layer.dst,
    )
# end def _parse_ipv6


def _parse_tcp(layer: ScapyPacket) -> TCPSegment:
    return TCPSegment(
        sport    = layer.sport,
        dport    = layer.dport,
        seq      = layer.seq,
        ack      = layer.ack,
        dataofs  = layer.dataofs,
        reserved = layer.reserved,
        flags    = int(layer.flags),
        window   = layer.window,
        chksum   = layer.chksum if layer.chksum is not None else 0,
        urgptr   = layer.urgptr,
        payload  = bytes(layer.payload),
    )
# end def _parse_tcp


def _parse_udp(layer: ScapyPacket) -> UDPDatagram:
    return UDPDatagram(
        sport   = layer.sport,
        dport   = layer.dport,
        len     = layer.len,
        chksum  = layer.chksum if layer.chksum is not None else 0,
        payload = bytes(layer.payload),
    )
# end def _parse_udp


def _parse_icmp(layer: ScapyPacket) -> ICMPMessage:
    return ICMPMessage(
        type    = layer.type,
        code    = layer.code,
        chksum  = layer.chksum if layer.chksum is not None else 0,
        id      = getattr(layer, "id", 0),
        seq     = getattr(layer, "seq", 0),
        payload = bytes(layer.payload),
    )
# end def _parse_icmp


def _parse_dns(layer: ScapyPacket) -> DNSMessage:
    return DNSMessage(
        id      = layer.id,
        qr      = layer.qr,
        opcode  = layer.opcode,
        aa      = layer.aa,
        tc      = layer.tc,
        rd      = layer.rd,
        ra      = layer.ra,
        z       = layer.z,
        rcode   = layer.rcode,
        qdcount = layer.qdcount,
        ancount = layer.ancount,
        nscount = layer.nscount,
        arcount = layer.arcount,
        summary = layer.summary(),
    )
# end def _parse_dns


# ---------------------------------------------------------------------------
# Main parsing function
# ---------------------------------------------------------------------------

# Maps scapy layer classes to their parser functions and target attribute name on PacketRecord
_LAYER_PARSERS_dct = {
    Ether : ("ethernet", _parse_ethernet),
    ARP   : ("arp",      _parse_arp),
    IP    : ("ipv4",     _parse_ipv4),
    IPv6  : ("ipv6",     _parse_ipv6),
    TCP   : ("tcp",      _parse_tcp),
    UDP   : ("udp",      _parse_udp),
    ICMP  : ("icmp",     _parse_icmp),
    DNS   : ("dns",      _parse_dns),
}


def parse_pcap(filepath: str) -> list[PacketRecord]:
    """Read a pcap file and return a list of PacketRecord objects, one per frame."""
    raw_packets_lst = rdpcap(filepath)
    packets_lst     = []

    for idx, scapy_pkt in enumerate(raw_packets_lst, start = 1):
        record = PacketRecord(
            index     = idx,
            timestamp = float(scapy_pkt.time),
            wire_len  = scapy_pkt.wirelen if hasattr(scapy_pkt, "wirelen") else len(scapy_pkt),
            cap_len   = len(scapy_pkt),
        )

        # Walk every layer in the packet and dispatch to the correct parser
        current_layer = scapy_pkt
        while current_layer and current_layer.__class__.__name__ != "NoPayload":
            layer_cls = type(current_layer)
            if layer_cls in _LAYER_PARSERS_dct:
                attr_name, parser_fn = _LAYER_PARSERS_dct[layer_cls]
                setattr(record, attr_name, parser_fn(current_layer))
            else:
                # Store unrecognised layers as raw bytes to avoid data loss
                record.unknowns.append(RawPayload(proto_name = layer_cls.__name__, raw_bytes = bytes(current_layer)))

            current_layer = current_layer.payload if hasattr(current_layer, "payload") else None
        # end for (layer walk)

        packets_lst.append(record)
    # end for (packet loop)

    return packets_lst
# end def parse_pcap


# ---------------------------------------------------------------------------
# CLI entry point + summary printer
# ---------------------------------------------------------------------------

def _print_summary(packets_lst: list[PacketRecord]) -> None:
    """Print a brief human-readable summary for each parsed packet."""
    for pkt in packets_lst:
        parts_lst = [f"#{pkt.index:>5}  ts={pkt.timestamp:.6f}  cap={pkt.cap_len}B"]

        if pkt.ethernet:
            parts_lst.append(f"ETH {pkt.ethernet.src} -> {pkt.ethernet.dst} ({pkt.ethernet.type_hex})")
        if pkt.arp:
            op_str = "req" if pkt.arp.op == 1 else "rep"
            parts_lst.append(f"ARP {pkt.arp.psrc} -> {pkt.arp.pdst} [{op_str}]")
        if pkt.ipv4:
            parts_lst.append(f"IPv4 {pkt.ipv4.src} -> {pkt.ipv4.dst}  ttl={pkt.ipv4.ttl}  proto={pkt.ipv4.proto}")
        if pkt.ipv6:
            parts_lst.append(f"IPv6 {pkt.ipv6.src} -> {pkt.ipv6.dst}  hlim={pkt.ipv6.hlim}")
        if pkt.tcp:
            parts_lst.append(f"TCP  :{pkt.tcp.sport} -> :{pkt.tcp.dport}  seq={pkt.tcp.seq}  flags={pkt.tcp.flags:#04x}")
        if pkt.udp:
            parts_lst.append(f"UDP  :{pkt.udp.sport} -> :{pkt.udp.dport}  len={pkt.udp.len}")
        if pkt.icmp:
            parts_lst.append(f"ICMP type={pkt.icmp.type}  code={pkt.icmp.code}  id={pkt.icmp.id}  seq={pkt.icmp.seq}")
        if pkt.dns:
            qr_str = "RSP" if pkt.dns.qr else "QRY"
            parts_lst.append(f"DNS  [{qr_str}] id={pkt.dns.id}  qd={pkt.dns.qdcount}  an={pkt.dns.ancount}")
        for unk in pkt.unknowns:
            parts_lst.append(f"??? {unk.proto_name} ({len(unk.raw_bytes)}B)")

        print("  |  ".join(parts_lst))
# end def _print_summary


def _sep(title: str) -> None:
    """Print a clearly visible section separator."""
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")
# end def _sep


# ---------------------------------------------------------------------------
# Example 1 – all TCP packets, highlighting dport
# ---------------------------------------------------------------------------

def example_tcp_dport(packets_lst: list[PacketRecord]) -> None:
    """
    Filter all TCP packets and print their source/destination IPs and ports.
    The dport field (destination port) is highlighted with '>>>' so it stands out.
    Pattern: access pkt.tcp  (the TCPSegment object) then its fields directly.
    """
    _sep("EXAMPLE 1 – TCP packets  |  emphasising dport")

    # Keep only packets that have a TCP layer (pkt.tcp is None when there is no TCP layer)
    tcp_packets_lst = [pkt for pkt in packets_lst if pkt.tcp is not None]
    print(f"  Total TCP packets found: {len(tcp_packets_lst)}\n")

    for pkt in tcp_packets_lst:
        src_ip  = pkt.ipv4.src if pkt.ipv4 else (pkt.ipv6.src if pkt.ipv6 else "?")
        dst_ip  = pkt.ipv4.dst if pkt.ipv4 else (pkt.ipv6.dst if pkt.ipv6 else "?")
        sport   = pkt.tcp.sport    # source port      – field from TCPSegment
        dport   = pkt.tcp.dport    # destination port – field from TCPSegment  <-- highlighted
        flags   = pkt.tcp.flags    # raw flags bitmask (int)
        seq     = pkt.tcp.seq      # sequence number

        # Decode the most common TCP flag combinations into a short label
        flag_str = ""
        if flags & 0x02: flag_str += "SYN "
        if flags & 0x10: flag_str += "ACK "
        if flags & 0x01: flag_str += "FIN "
        if flags & 0x04: flag_str += "RST "
        if flags & 0x08: flag_str += "PSH "
        flag_str = flag_str.strip() or f"0x{flags:02x}"

        print(f"  #{pkt.index:>4}  {src_ip}:{sport}  ->  {dst_ip}:>>> {dport} <<<   flags=[{flag_str}]  seq={seq}")
# end def example_tcp_dport


# ---------------------------------------------------------------------------
# Example 2 – TCP connections to well-known ports (web traffic)
# ---------------------------------------------------------------------------

def example_tcp_web_traffic(packets_lst: list[PacketRecord]) -> None:
    """
    Among TCP packets, keep only those whose dport is 80 or 443 (HTTP / HTTPS).
    Shows how to combine two field conditions in the filter.
    """
    _sep("EXAMPLE 2 – TCP packets to port 80 (HTTP) or 443 (HTTPS)")

    web_ports_lst   = [80, 443]
    # Filter: must have TCP layer AND dport must be in our list of web ports
    web_pkts_lst    = [pkt for pkt in packets_lst if pkt.tcp is not None and pkt.tcp.dport in web_ports_lst]
    print(f"  HTTP/HTTPS packets found: {len(web_pkts_lst)}\n")

    for pkt in web_pkts_lst:
        src_ip    = pkt.ipv4.src if pkt.ipv4 else "?"
        dst_ip    = pkt.ipv4.dst if pkt.ipv4 else "?"
        protocol  = "HTTPS" if pkt.tcp.dport == 443 else "HTTP"
        pay_len   = len(pkt.tcp.payload)   # payload field from TCPSegment

        print(f"  #{pkt.index:>4}  [{protocol}]  {src_ip}:{pkt.tcp.sport}  ->  {dst_ip}:{pkt.tcp.dport}   payload={pay_len}B")
# end def example_tcp_web_traffic


# ---------------------------------------------------------------------------
# Example 3 – UDP packets, highlighting dport and payload size
# ---------------------------------------------------------------------------

def example_udp_dport(packets_lst: list[PacketRecord]) -> None:
    """
    Filter all UDP packets and display dport and payload length.
    Same pattern as TCP but accessing pkt.udp (UDPDatagram object).
    """
    _sep("EXAMPLE 3 – UDP packets  |  dport + payload size")

    udp_pkts_lst = [pkt for pkt in packets_lst if pkt.udp is not None]
    print(f"  Total UDP packets found: {len(udp_pkts_lst)}\n")

    for pkt in udp_pkts_lst:
        src_ip   = pkt.ipv4.src if pkt.ipv4 else (pkt.ipv6.src if pkt.ipv6 else "?")
        dst_ip   = pkt.ipv4.dst if pkt.ipv4 else (pkt.ipv6.dst if pkt.ipv6 else "?")
        sport    = pkt.udp.sport     # source port      – field from UDPDatagram
        dport    = pkt.udp.dport     # destination port – field from UDPDatagram
        udp_len  = pkt.udp.len       # total UDP length (header 8B + payload)
        pay_len  = len(pkt.udp.payload)

        print(f"  #{pkt.index:>4}  {src_ip}:{sport}  ->  {dst_ip}:{dport}   udp.len={udp_len}B  payload={pay_len}B")
# end def example_udp_dport


# ---------------------------------------------------------------------------
# Example 4 – DNS queries vs responses
# ---------------------------------------------------------------------------

def example_dns_queries_vs_responses(packets_lst: list[PacketRecord]) -> None:
    """
    Filter DNS packets and split them into queries (qr=0) and responses (qr=1).
    Shows how to filter on a nested field two levels deep: pkt.dns.qr
    """
    _sep("EXAMPLE 4 – DNS  |  queries vs responses")

    dns_pkts_lst  = [pkt for pkt in packets_lst if pkt.dns is not None]
    # pkt.dns.qr == 0 means query; == 1 means response
    queries_lst   = [pkt for pkt in dns_pkts_lst if pkt.dns.qr == 0]
    responses_lst = [pkt for pkt in dns_pkts_lst if pkt.dns.qr == 1]
    print(f"  DNS packets total: {len(dns_pkts_lst)}   queries: {len(queries_lst)}   responses: {len(responses_lst)}\n")

    print("  -- Queries --")
    for pkt in queries_lst:
        src_ip = pkt.ipv4.src if pkt.ipv4 else "?"
        # pkt.dns fields: id, qr, qdcount, ancount, summary
        print(f"  #{pkt.index:>4}  {src_ip}  dns.id={pkt.dns.id:#06x}  questions={pkt.dns.qdcount}  |  {pkt.dns.summary}")

    print("\n  -- Responses --")
    for pkt in responses_lst:
        src_ip  = pkt.ipv4.src if pkt.ipv4 else "?"
        rcode   = pkt.dns.rcode   # 0 = NOERROR, 3 = NXDOMAIN, etc.
        rcode_s = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(rcode, str(rcode))
        print(f"  #{pkt.index:>4}  {src_ip}  dns.id={pkt.dns.id:#06x}  answers={pkt.dns.ancount}  rcode={rcode_s}  |  {pkt.dns.summary}")
# end def example_dns_queries_vs_responses


# ---------------------------------------------------------------------------
# Example 5 – ICMP echo request / reply pairs
# ---------------------------------------------------------------------------

def example_icmp_echo(packets_lst: list[PacketRecord]) -> None:
    """
    Filter ICMP packets and distinguish echo-requests (type=8) from echo-replies (type=0).
    Uses pkt.icmp.type and pkt.icmp.seq to match pairs visually.
    """
    _sep("EXAMPLE 5 – ICMP  |  echo requests and replies (ping)")

    icmp_pkts_lst = [pkt for pkt in packets_lst if pkt.icmp is not None]
    # type 8 = Echo Request  |  type 0 = Echo Reply
    requests_lst  = [pkt for pkt in icmp_pkts_lst if pkt.icmp.type == 8]
    replies_lst   = [pkt for pkt in icmp_pkts_lst if pkt.icmp.type == 0]
    print(f"  ICMP total: {len(icmp_pkts_lst)}   echo-requests: {len(requests_lst)}   echo-replies: {len(replies_lst)}\n")

    for pkt in icmp_pkts_lst:
        src_ip   = pkt.ipv4.src if pkt.ipv4 else "?"
        dst_ip   = pkt.ipv4.dst if pkt.ipv4 else "?"
        kind     = "REQUEST" if pkt.icmp.type == 8 else ("REPLY  " if pkt.icmp.type == 0 else f"type={pkt.icmp.type}")
        # pkt.icmp fields: type, code, id, seq, payload
        print(f"  #{pkt.index:>4}  [{kind}]  {src_ip}  ->  {dst_ip}   id={pkt.icmp.id}  seq={pkt.icmp.seq}  payload={len(pkt.icmp.payload)}B")
# end def example_icmp_echo


# ---------------------------------------------------------------------------
# Example 6 – ARP requests / replies  (who-has / is-at)
# ---------------------------------------------------------------------------

def example_arp(packets_lst: list[PacketRecord]) -> None:
    """
    Filter ARP packets and print who is asking about whom (op=1 request)
    and who answered (op=2 reply).  Accesses pkt.arp fields directly.
    """
    _sep("EXAMPLE 6 – ARP  |  who-has (request) and is-at (reply)")

    arp_pkts_lst = [pkt for pkt in packets_lst if pkt.arp is not None]
    print(f"  ARP packets found: {len(arp_pkts_lst)}\n")

    for pkt in arp_pkts_lst:
        # pkt.arp fields: op, hwsrc, psrc, hwdst, pdst
        if pkt.arp.op == 1:    # who-has request
            print(f"  #{pkt.index:>4}  [REQUEST]  {pkt.arp.psrc} ({pkt.arp.hwsrc})  asks: who has {pkt.arp.pdst} ?")
        elif pkt.arp.op == 2:  # is-at reply
            print(f"  #{pkt.index:>4}  [REPLY  ]  {pkt.arp.psrc} ({pkt.arp.hwsrc})  says: {pkt.arp.pdst} is at {pkt.arp.hwsrc}")
        else:
            print(f"  #{pkt.index:>4}  [op={pkt.arp.op}]  {pkt.arp.psrc} -> {pkt.arp.pdst}")
# end def example_arp


# ---------------------------------------------------------------------------
# Example 7 – IPv4 cross-fields: TTL outliers + fragmented packets
# ---------------------------------------------------------------------------

def example_ipv4_ttl_and_fragments(packets_lst: list[PacketRecord]) -> None:
    """
    Two IPv4 sub-examples in one:
      a) Packets with a surprisingly low TTL (<= 5) – may indicate routing issues or crafted packets.
      b) Fragmented packets (frag > 0 or the MF flag set in the flags field, bit 0x1).
    Demonstrates filtering on numeric field comparisons and bitwise checks.
    """
    _sep("EXAMPLE 7 – IPv4  |  a) low-TTL packets   b) fragmented packets")

    ipv4_pkts_lst    = [pkt for pkt in packets_lst if pkt.ipv4 is not None]

    # a) Low TTL: pkt.ipv4.ttl is a plain int, so simple comparison works
    low_ttl_lst      = [pkt for pkt in ipv4_pkts_lst if pkt.ipv4.ttl <= 5]
    # b) Fragmented: frag offset > 0  OR  More Fragments (MF) flag is set (bit 0x1 of flags)
    fragmented_lst   = [pkt for pkt in ipv4_pkts_lst if pkt.ipv4.frag > 0 or (pkt.ipv4.flags & 0x1)]

    print(f"  IPv4 packets total: {len(ipv4_pkts_lst)}")
    print(f"  Low-TTL (<= 5):     {len(low_ttl_lst)}")
    print(f"  Fragmented:         {len(fragmented_lst)}\n")

    print("  -- Low TTL --")
    for pkt in low_ttl_lst:
        # pkt.ipv4 fields: src, dst, ttl, proto, id
        print(f"  #{pkt.index:>4}  {pkt.ipv4.src}  ->  {pkt.ipv4.dst}   TTL={pkt.ipv4.ttl}  proto={pkt.ipv4.proto}  ip.id={pkt.ipv4.id:#06x}")

    print("\n  -- Fragmented --")
    for pkt in fragmented_lst:
        mf_flag = bool(pkt.ipv4.flags & 0x1)   # More Fragments flag
        print(f"  #{pkt.index:>4}  {pkt.ipv4.src}  ->  {pkt.ipv4.dst}   frag_offset={pkt.ipv4.frag}  MF={mf_flag}  ip.id={pkt.ipv4.id:#06x}")
# end def example_ipv4_ttl_and_fragments


# ---------------------------------------------------------------------------
# Example 8 – cross-layer query: TCP SYN packets destined for non-standard ports
# ---------------------------------------------------------------------------

def example_tcp_syn_non_standard(packets_lst: list[PacketRecord]) -> None:
    """
    Combines two layers in a single filter: must have IPv4 AND TCP, the TCP
    SYN flag must be set (bit 0x02), and dport must NOT be in a known set.
    This pattern shows how to reference fields from two different layer objects
    (pkt.ipv4 and pkt.tcp) inside the same list-comprehension condition.
    """
    _sep("EXAMPLE 8 – Cross-layer: TCP SYN to non-standard ports")

    known_ports_lst  = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443]
    # Condition: has both IPv4 and TCP layers, SYN flag set, dport not well-known
    syn_odd_lst      = [
        pkt for pkt in packets_lst
        if pkt.ipv4 is not None
        and pkt.tcp  is not None
        and (pkt.tcp.flags & 0x02)          # SYN flag
        and pkt.tcp.dport not in known_ports_lst
    ]
    print(f"  TCP SYN to non-standard ports: {len(syn_odd_lst)}\n")

    for pkt in syn_odd_lst:
        # Access pkt.ipv4 and pkt.tcp fields in the same print statement
        print(f"  #{pkt.index:>4}  {pkt.ipv4.src}:{pkt.tcp.sport}  ->  {pkt.ipv4.dst}:{pkt.tcp.dport}   ttl={pkt.ipv4.ttl}  win={pkt.tcp.window}")
# end def example_tcp_syn_non_standard


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description = "Parse a .pcap file into typed Python objects and show query examples.")
    parser.add_argument("pcap_file", help = "Path to the .pcap file to parse")
    parser.add_argument("--summary", action = "store_true", default = False, help = "Also print the raw one-line summary for every packet")
    args = parser.parse_args()

    print(f"[*] Reading '{args.pcap_file}' ...")
    packets_lst = parse_pcap(args.pcap_file)
    print(f"[*] Parsed {len(packets_lst)} packet(s).")

    if args.summary:
        _sep("RAW SUMMARY  (one line per packet)")
        _print_summary(packets_lst)

    # --- Run all examples against the parsed list ---
    example_tcp_dport(packets_lst)               # Ex 1 – all TCP, highlight dport
    example_tcp_web_traffic(packets_lst)         # Ex 2 – TCP port 80 / 443
    example_udp_dport(packets_lst)               # Ex 3 – all UDP, dport + payload
    example_dns_queries_vs_responses(packets_lst)# Ex 4 – DNS qr split
    example_icmp_echo(packets_lst)               # Ex 5 – ICMP ping pairs
    example_arp(packets_lst)                     # Ex 6 – ARP who-has / is-at
    example_ipv4_ttl_and_fragments(packets_lst)  # Ex 7 – IPv4 TTL + fragments
    example_tcp_syn_non_standard(packets_lst)    # Ex 8 – cross-layer SYN scan detection

    print("\n[*] Done.\n")
# end def main


if __name__ == "__main__":
    main()
