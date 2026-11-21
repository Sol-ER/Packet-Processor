import sys # This import is included in every Python 3 installation so it should work
import numpy as np


# CSCI.351.01 - Data Comm & Networks
# Programming Part 1
# George Scheper, Ethan Ricker, Ricky Leung

# Sources
# Title                                 Link
# RFC 791                               https://www.rfc-editor.org/info/rfc791/
# RFC 9293                              https://www.rfc-editor.org/info/rfc9293/
# Network Math - the Mighty Checksum!   https://www.youtube.com/watch?v=7LniwyiH0SM
# RFC 8200                              https://www.rfc-editor.org/info/rfc8200/
# RFC 826                               https://www.rfc-editor.org/info/rfc826/


MAX_16_BIT_VALUE = 0xffff
L3_BIN_WIDTH = 250


def parseNumber(numberText: str) -> int:
    """Convert supported user input into an integer.

    Binary input must begin with 0b, hexadecimal input must begin with
    0x, and input without a prefix is interpreted as base 10.

    Arguments:
    numberText -- The number entered by the user.

    Returns:
    The number as an integer between 0 and 65535.
    """
    numberText = numberText.strip().lower()

    # Determine the input base from its prefix
    if numberText.startswith("0b"):
        digits = numberText[2:]
        base = 2
        validDigits = "01"
    elif numberText.startswith("0x"):
        digits = numberText[2:]
        base = 16
        validDigits = "0123456789abcdef"
    else:
        digits = numberText
        base = 10
        validDigits = "0123456789"

    # Verify the number contains digits valid for its base
    if not digits or any(digit not in validDigits for digit in digits):
        raise ValueError(
            "Enter a decimal number, or use the 0b or 0x prefix."
        )

    value = int(digits, base)

    # Limit the converter to an unsigned two-byte value
    if value > MAX_16_BIT_VALUE:
        raise ValueError("The number must be between 0 and 65535.")

    return value


def formatConversion(numberText: str) -> str:
    """Format a number as 16-bit binary, hexadecimal, and base 10.

    Arguments:
    numberText -- The binary, hexadecimal, or decimal input.

    Returns:
    A formatted string containing all three representations.
    """
    value = parseNumber(numberText)

    return (
        f"Binary:      0b{value:016b}\n"
        f"Hexadecimal: 0x{value:04x}\n"
        f"Base 10:     {value}"
    )


class ethernetIIHeader:
    """Ethernet II header.

    This class represents the ethernet header, either Ethernet II or 802.3.
    """

    def __init__(self, dst:str, src:str, type:int):
        self.etherdst = dst
        self.ethersrc = src
        self.type = type

    def __str__(self):
        return (
            "Ethernet Header\n"
            f"  Destination address:  {self.etherdst}\n"
            f"  Source address:       {self.ethersrc}\n"
            f"  Length/Type:          {self.getEtherType()}"
        )

    def getEtherType(self) -> str:
        if self.type <= 1500:
            return f"IEEE 802.3 payload length ({self.type} bytes)"
        elif self.type == 0x0800:
            return "IPv4"
        elif self.type == 0x0806:
            return "ARP"
        elif self.type == 0x86dd:
            return "IPv6"
        return f"type \"0x{self.type:04x}\" not listed"


class ipv4Header:
    """ipv4 header.

    This class represents the IPv4 header, if it's available.
    """
    def __init__(self, version: int, ihl: int, dscp: int, ecn: int,
                 totalLength: int, identification: int, flags: int,
                 fragmentOffset: int, ttl: int, protocol: int,
                 checksum: int, source: str, destination: str,
                 options: list[int]):
        self.version = version
        self.ihl = ihl
        self.headerLength = ihl * 4
        self.dscp = dscp
        self.ecn = ecn
        self.totalLength = totalLength
        self.identification = identification
        self.flags = flags
        self.fragmentOffset = fragmentOffset
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = checksum
        self.source = source
        self.destination = destination
        self.options = options

    def getProtocol(self) -> str:
        protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protocols.get(self.protocol, "Unknown")

    def calculate_checksum(self) -> str:
        src_bytes = [int(octet) for octet in self.source.split(".")]
        dst_bytes = [int(octet) for octet in self.destination.split(".")]

        ver_ihl = (self.version << 4) | (self.ihl & 0x0F)
        tos = (self.dscp << 2) | (self.ecn & 0x03)
        flags_fragment = ((self.flags & 0x07) << 13) | (
                self.fragmentOffset & 0x1FFF
        )

        header_bytes = bytearray(
            [
                ver_ihl,
                tos,
                self.totalLength >> 8,
                self.totalLength & 0xFF,
                self.identification >> 8,
                self.identification & 0xFF,
                flags_fragment >> 8,
                flags_fragment & 0xFF,
                self.ttl,
                self.protocol,
                0,
                0,  # Checksum bytes set to 0
                src_bytes[0],
                src_bytes[1],
                src_bytes[2],
                src_bytes[3],
                dst_bytes[0],
                dst_bytes[1],
                dst_bytes[2],
                dst_bytes[3],
            ]
        )

        if self.options:
            header_bytes.extend(self.options)
        checksum_sum = 0
        for i in range(0, len(header_bytes), 2):
            word = (header_bytes[i] << 8) + header_bytes[i + 1]
            checksum_sum += word
        while checksum_sum >> 16:
            checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
        final_checksum = ~checksum_sum & 0xFFFF
        return f"{final_checksum:04x}"

    def verify_checksum(self) -> bool:
        return f"{self.checksum:04x}" == self.calculate_checksum()

    def __str__(self) -> str:
        options = "None"
        if self.options:
            options = " ".join(format(byte, "02x") for byte in self.options)

        is_valid = self.verify_checksum()

        return (
            "IPv4 Header\n"
            f"  Version:              {self.version}\n"
            f"  Header length:        {self.headerLength} bytes\n"
            f"  DSCP:                 {self.dscp}\n"
            f"  ECN:                  {self.ecn}\n"
            f"  Total length:         {self.totalLength} bytes\n"
            f"  Identification:       0x{self.identification:04x}\n"
            f"  Flags:                0b{self.flags:03b}\n"
            f"  Fragment offset:      {self.fragmentOffset}\n"
            f"  Time to live:         {self.ttl}\n"
            f"  Protocol:             {self.getProtocol()} ({self.protocol})\n"
            f"  Header checksum:      0x{self.checksum:04x}\n"
            f"  Source address:       {self.source}\n"
            f"  Destination address:  {self.destination}\n"
            f"  Options:              {options}\n"
            f"  Calculated checksum   0x{self.calculate_checksum()}\n"
            f"  {'Calculated checksum matches given checksum' if is_valid else 'Calculated checksum does not match given checksum'}"
        )


class ipv6Header:
    """ipv6 header.

    This class represents the IPv6 header, if it's available.
    """
    def __init__(self, version: int, trafficClass: int, flowLabel: int,
                 payloadLength: int, nextHeader: int, hopLimit: int,
                 source: str, destination: str):
        self.version = version
        self.trafficClass = trafficClass
        self.flowLabel = flowLabel
        self.payloadLength = payloadLength
        self.nextHeader = nextHeader
        self.hopLimit = hopLimit
        self.source = source
        self.destination = destination

    def getNextHeader(self) -> str:
        headers = {
            0: "Hop-by-Hop Options", 6: "TCP", 17: "UDP",
            43: "Routing", 44: "Fragment", 58: "ICMPv6",
            60: "Destination Options"
        }
        return headers.get(self.nextHeader, "Unknown")

    def __str__(self) -> str:
        return (
            "IPv6 Header\n"
            f"  Version:              {self.version}\n"
            f"  Traffic class:        {self.trafficClass}\n"
            f"  Flow label:           0x{self.flowLabel:05x}\n"
            f"  Payload length:       {self.payloadLength} bytes\n"
            f"  Next header:          "
            f"{self.getNextHeader()} ({self.nextHeader})\n"
            f"  Hop limit:            {self.hopLimit}\n"
            f"  Source address:       {self.source}\n"
            f"  Destination address:  {self.destination}"
        )


class arpHeader:
    """ARP header.

    This class represents the ARP header from an ARP request.
    """
    def __init__(self, hardwareType: int, protocolType: int,
                 hardwareLength: int, protocolLength: int,
                 operation: int, senderHardware: str,
                 senderProtocol: str, targetHardware: str,
                 targetProtocol: str):
        self.hardwareType = hardwareType
        self.protocolType = protocolType
        self.hardwareLength = hardwareLength
        self.protocolLength = protocolLength
        self.operation = operation
        self.senderHardware = senderHardware
        self.senderProtocol = senderProtocol
        self.targetHardware = targetHardware
        self.targetProtocol = targetProtocol

    def getHardwareType(self) -> str:
        if self.hardwareType == 1:
            return "Ethernet"
        return "Unknown"

    def getProtocolType(self) -> str:
        if self.protocolType == 0x0800:
            return "IPv4"
        return "Unknown"

    def getOperation(self) -> str:
        operations = {1: "Request", 2: "Reply"}
        return operations.get(self.operation, "Unknown")

    def __str__(self) -> str:
        return (
            "ARP Header\n"
            f"  Hardware type:        "
            f"{self.getHardwareType()} ({self.hardwareType})\n"
            f"  Protocol type:        "
            f"{self.getProtocolType()} (0x{self.protocolType:04x})\n"
            f"  Hardware addr length: {self.hardwareLength} bytes\n"
            f"  Protocol addr length: {self.protocolLength} bytes\n"
            f"  Operation:            "
            f"{self.getOperation()} ({self.operation})\n"
            f"  Sender hardware addr: {self.senderHardware}\n"
            f"  Sender protocol addr: {self.senderProtocol}\n"
            f"  Target hardware addr: {self.targetHardware}\n"
            f"  Target protocol addr: {self.targetProtocol}"
        )


class ieee8022Header:
    """IEEE 802.2 header.

    This class represents the 802.2 header, it contains the fields
    related to that area of the frame.
    """
    def __init__(self, payloadLength: int, dsap: int, ssap: int,
                 control: int, controlLength: int, oui=None,
                 protocolId=None):
        self.payloadLength = payloadLength
        self.dsap = dsap
        self.ssap = ssap
        self.control = control
        self.controlLength = controlLength
        self.oui = oui
        self.protocolId = protocolId

    def getProtocol(self) -> str:
        if self.dsap == 0x42 and self.ssap == 0x42:
            return "Spanning Tree Protocol"
        elif self.oui == 0x00000c and self.protocolId == 0x2000:
            return "Cisco Discovery Protocol"
        elif self.dsap == 0xaa and self.ssap == 0xaa:
            return "SNAP"
        return "Unknown"

    def __str__(self) -> str:
        output = (
            "IEEE 802.2 LLC Header\n"
            f"  Payload length:       {self.payloadLength} bytes\n"
            f"  Destination SAP:      0x{self.dsap:02x}\n"
            f"  Source SAP:           0x{self.ssap:02x}\n"
            f"  Control:              "
            f"0x{self.control:0{self.controlLength * 2}x}\n"
            f"  Protocol:             {self.getProtocol()}"
        )

        # Include SNAP fields when the LLC header contains them
        if self.oui is not None and self.protocolId is not None:
            output += (
                f"\n  Organization ID:      0x{self.oui:06x}\n"
                f"  Protocol ID:          0x{self.protocolId:04x}"
            )
        return output


class tcpHeader:
    """TCP header.

    This class represents the TCP header in a TCP request.
    """
    def __init__(self, sourcePort: int, destinationPort: int,
                 sequenceNumber: int, acknowledgmentNumber: int,
                 dataOffset: int, reserved: int, flags: int,
                 windowSize: int, checksum: int, urgentPointer: int,
                 options: list[int]):
        self.sourcePort = sourcePort
        self.destinationPort = destinationPort
        self.sequenceNumber = sequenceNumber
        self.acknowledgmentNumber = acknowledgmentNumber
        self.dataOffset = dataOffset
        self.headerLength = dataOffset * 4
        self.reserved = reserved
        self.flags = flags
        self.windowSize = windowSize
        self.checksum = checksum
        self.urgentPointer = urgentPointer
        self.options = options
        self.src_ip = None
        self.dest_ip = None

    def getFlags(self) -> str:
        flagNames = (
            (0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"),
            (0x020, "URG"), (0x010, "ACK"), (0x008, "PSH"),
            (0x004, "RST"), (0x002, "SYN"), (0x001, "FIN")
        )
        enabled = [name for mask, name in flagNames if self.flags & mask]
        return ", ".join(enabled) if enabled else "None"

    def calculate_checksum(self, payload_bytes: bytes = b"") -> str:
        src_bytes = [int(octet) for octet in self.src_ip.split(".")]
        dest_bytes = [int(octet) for octet in self.dest_ip.split(".")]
        data_offset_reserved_ns = (self.dataOffset << 12) | ((self.reserved & 0x07) << 9) | (self.flags & 0x1FF)

        tcp_header_bytes = bytearray([
            self.sourcePort >> 8, self.sourcePort & 0xFF,
            self.destinationPort >> 8, self.destinationPort & 0xFF,
            self.sequenceNumber >> 24 & 0xFF, (self.sequenceNumber >> 16) & 0xFF, (self.sequenceNumber >> 8) & 0xFF,
            self.sequenceNumber & 0xFF,
            (self.acknowledgmentNumber >> 24) & 0xFF, (self.acknowledgmentNumber >> 16) & 0xFF,
            (self.acknowledgmentNumber >> 8) & 0xFF, self.acknowledgmentNumber & 0xFF,
            data_offset_reserved_ns >> 8, data_offset_reserved_ns & 0xFF,
            self.windowSize >> 8, self.windowSize & 0xFF,
            0, 0,  # Checksum bytes set to 0 for calculation
            self.urgentPointer >> 8, self.urgentPointer & 0xFF
        ])

        if self.options:
            tcp_header_bytes.extend(self.options)
        tcp_segment = bytes(tcp_header_bytes) + payload_bytes
        tcp_length = len(tcp_segment)
        pseudo_header = bytearray([
            src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3],
            dest_bytes[0], dest_bytes[1], dest_bytes[2], dest_bytes[3],
            0,  # Reserved / Zero
            6,  # Protocol (6 for TCP)
            tcp_length >> 8, tcp_length & 0xFF
        ])

        full_payload = bytes(pseudo_header) + tcp_segment
        if len(full_payload) % 2 != 0:
            full_payload += b'\x00'
        checksum_sum = 0
        for i in range(0, len(full_payload), 2):
            word = (full_payload[i] << 8) + full_payload[i + 1]
            checksum_sum += word
        while checksum_sum >> 16:
            checksum_sum = (checksum_sum & 0xFFFF) + (checksum_sum >> 16)
        final_checksum = ~checksum_sum & 0xFFFF
        return f"{final_checksum:04x}"

    def verify_checksum(self, payload_bytes: bytes = b"") -> bool:
        return f"{self.checksum:04x}" == self.calculate_checksum(payload_bytes)

    def __str__(self) -> str:
        options = "None"
        if self.options:
            options = " ".join(format(byte, "02x") for byte in self.options)

        is_valid = self.verify_checksum()

        return (
            "TCP Header\n"
            f"  Source port:          {self.sourcePort}\n"
            f"  Destination port:     {self.destinationPort}\n"
            f"  Sequence number:      {self.sequenceNumber}\n"
            f"  Acknowledgment no.:   {self.acknowledgmentNumber}\n"
            f"  Header length:        {self.headerLength} bytes\n"
            f"  Reserved bits:        0b{self.reserved:03b}\n"
            f"  Flags:                {self.getFlags()}\n"
            f"  Window size:          {self.windowSize}\n"
            f"  Checksum:             0x{self.checksum:04x}\n"
            f"  Urgent pointer:       {self.urgentPointer}\n"
            f"  Options:              {options}\n"
            f"  Calculated checksum   0x{self.calculate_checksum()}\n"
            f"  {'Calculated checksum matches given checksum' if is_valid else 'Calculated checksum does not match given checksum'}"
        )


class message:
    """The cummulative message.

    All the headers involved in a packet. Some may be omitted if they
    are not present.
    """
    def __init__(self, ethernetHeader: ethernetIIHeader, ipHeader=None,
                 tcpHeader=None, arpHeader=None, llcHeader=None,
                 packetNumber=0, packetDescription="",
                 timestampSeconds=0.0, frameLength=0):
        self.ethernetHeader = ethernetHeader
        self.ipHeader = ipHeader
        self.tcpHeader = tcpHeader
        self.arpHeader = arpHeader
        self.llcHeader = llcHeader
        self.packetNumber = packetNumber
        self.packetDescription = packetDescription
        self.timestampSeconds = timestampSeconds
        self.frameLength = frameLength


def classifyL2Protocol(msg: message) -> str:
    """Return the Layer 2 protocol label for a captured message."""
    eth = msg.ethernetHeader
    if eth.type <= 1500:
        if msg.llcHeader is not None:
            llc_proto = msg.llcHeader.getProtocol()
            if llc_proto != "Unknown":
                return f"IEEE 802.3 / LLC ({llc_proto})"
        return "IEEE 802.3"
    if eth.type == 0x0800:
        return "Ethernet II (IPv4)"
    if eth.type == 0x0806:
        return "Ethernet II (ARP)"
    if eth.type == 0x86dd:
        return "Ethernet II (IPv6)"
    return f"Ethernet II (0x{eth.type:04x})"


def classifyL3Protocol(msg: message) -> str | None:
    """Return the Layer 3 protocol label, or None if no L3 header exists."""
    if isinstance(msg.ipHeader, ipv4Header):
        return "IPv4"
    if isinstance(msg.ipHeader, ipv6Header):
        return "IPv6"
    if msg.arpHeader is not None:
        return "ARP"
    return None


def classifyL4Protocol(msg: message) -> str | None:
    """Return the Layer 4 protocol label, or None if not applicable."""
    if isinstance(msg.ipHeader, ipv4Header):
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return proto_map.get(
            msg.ipHeader.protocol, f"Other IPv4 ({msg.ipHeader.protocol})"
        )
    if isinstance(msg.ipHeader, ipv6Header):
        proto_map = {6: "TCP", 17: "UDP", 58: "ICMPv6"}
        return proto_map.get(
            msg.ipHeader.nextHeader,
            f"Other IPv6 ({msg.ipHeader.nextHeader})",
        )
    return None


def getL3PacketSize(msg: message) -> int | None:
    """Return the Layer 3 packet size in bytes, or None if not L3."""
    if isinstance(msg.ipHeader, ipv4Header):
        return msg.ipHeader.totalLength
    if isinstance(msg.ipHeader, ipv6Header):
        return 40 + msg.ipHeader.payloadLength
    if msg.arpHeader is not None:
        arp = msg.arpHeader
        return 8 + (2 * arp.hardwareLength) + (2 * arp.protocolLength)
    return None


def computeProtocolStats(messages: list[message]) -> dict[str, dict[str, int]]:
    """Compute packet counts for L2, L3, and L4 protocols."""
    l2_counts: dict[str, int] = {}
    l3_counts: dict[str, int] = {}
    l4_counts: dict[str, int] = {}

    for msg in messages:
        l2 = classifyL2Protocol(msg)
        l2_counts[l2] = l2_counts.get(l2, 0) + 1

        l3 = classifyL3Protocol(msg)
        if l3 is not None:
            l3_counts[l3] = l3_counts.get(l3, 0) + 1

        l4 = classifyL4Protocol(msg)
        if l4 is not None:
            l4_counts[l4] = l4_counts.get(l4, 0) + 1

    return {
        "L2": dict(sorted(l2_counts.items(), key=lambda x: (-x[1], x[0]))),
        "L3": dict(sorted(l3_counts.items(), key=lambda x: (-x[1], x[0]))),
        "L4": dict(sorted(l4_counts.items(), key=lambda x: (-x[1], x[0]))),
    }


def computeL3SizeStats(
    messages: list[message], binWidth: int = L3_BIN_WIDTH
) -> tuple[list[tuple[str, int]], int]:
    """Bin L3 packet sizes into fixed byte increments using numpy."""
    sizes = [s for msg in messages if (s := getL3PacketSize(msg)) is not None]
    if not sizes:
        return [], 0

    arr = np.array(sizes, dtype=np.int64)
    max_val = int(arr.max())
    upper_bound = ((max_val // binWidth) + 1) * binWidth
    edges = np.arange(0, upper_bound + binWidth, binWidth)
    counts, _ = np.histogram(arr, bins=edges)

    bins: list[tuple[str, int]] = []
    for i, count in enumerate(counts):
        low = int(edges[i])
        high = int(edges[i + 1]) - 1
        bins.append((f"{low}-{high} B", int(count)))

    return bins, len(sizes)


def formatStatisticsReport(messages: list[message]) -> str:
    """Format protocol counts and 250-byte L3 packet size statistics."""
    total_packets = len(messages)
    stats = computeProtocolStats(messages)
    size_bins, total_l3 = computeL3SizeStats(messages, L3_BIN_WIDTH)

    lines = [
        "=" * 70,
        "PACKET & PROTOCOL STATISTICS",
        "=" * 70,
        f"Total Captured Frames: {total_packets}",
        "",
        "Layer 2 (Data Link) Protocols:",
    ]

    if stats["L2"]:
        for proto, count in stats["L2"].items():
            pct = (count / total_packets * 100) if total_packets else 0.0
            lines.append(f"  {proto:<32} {count:>6}  ({pct:5.1f}%)")
    else:
        lines.append("  None")

    lines.append("")
    lines.append("Layer 3 (Network) Protocols:")
    if stats["L3"]:
        for proto, count in stats["L3"].items():
            pct = (count / total_packets * 100) if total_packets else 0.0
            lines.append(f"  {proto:<32} {count:>6}  ({pct:5.1f}%)")
    else:
        lines.append("  None")

    lines.append("")
    lines.append("Layer 4 (Transport) Protocols:")
    if stats["L4"]:
        for proto, count in stats["L4"].items():
            pct = (count / total_packets * 100) if total_packets else 0.0
            lines.append(f"  {proto:<32} {count:>6}  ({pct:5.1f}%)")
    else:
        lines.append("  None")

    lines.append("")
    lines.append(
        f"Layer 3 Packet Sizes ({L3_BIN_WIDTH}-byte bins, {total_l3} L3 packets):"
    )
    if size_bins:
        for label, count in size_bins:
            pct = (count / total_l3 * 100) if total_l3 else 0.0
            lines.append(f"  {label:<18} {count:>6}  ({pct:5.1f}%)")
    else:
        lines.append("  No Layer 3 packets found.")

    lines.append("=" * 70)
    return "\n".join(lines)


def processPacketTimestamp(packetDescription: str) -> float:
    """Processes a packet timestamp.

    Take the timestamp from a packet description and return the number
    of seconds since midnight. Fractional seconds are preserved for
    later packets-per-second statistics.

    Arguments:
    packetDescription -- The description containing the timestamp.

    Returns:
    The timestamp as seconds since midnight.
    """
    # Separate the clock time from the fractional second groups
    timestamp = packetDescription.split()[0]
    timestampParts = timestamp.split(",")
    clockParts = timestampParts[0].split(":")

    # Convert hours, minutes, and seconds to seconds since midnight
    hours = int(clockParts[0])
    minutes = int(clockParts[1])
    seconds = int(clockParts[2])
    timestampSeconds = (hours * 3600) + (minutes * 60) + seconds

    # Convert all comma-separated fractional groups to a decimal value
    if len(timestampParts) > 1:
        fractionDigits = "".join(timestampParts[1:])
        timestampSeconds += int(fractionDigits) / (10 ** len(fractionDigits))

    return timestampSeconds


def processEthernetHeader(data:list[int]):
    """Processes the ethernet header data.

    Take the data from the input file and parse into an instance of the
    ethernet header class.

    Arguments:
    data -- The data containing the ethernet header information.

    Returns:
    An instance of the ethernet class
    """
    # Process ethernet destination address
    dst = ""
    for i in range(6):
        dst = dst + format(data.pop(0), "02x") + ":"
    dst = dst[:-1]

    # Process ethernet source address
    src = ""
    for i in range(6):
        src = src + format(data.pop(0), "02x") + ":"
    src = src[:-1]

    # Process ethertype
    type = 0
    for i in range(2):
        type = type << 8
        type = type | data.pop(0)

    # Init ethernet headers
    return ethernetIIHeader(dst, src, type)


def processIEEE8022Header(data: list[int],
                          payloadLength: int) -> ieee8022Header:
    """Processes the IEEE 802.2 header data.

    Take the data from the input file and payload length and return an
    instance of the 802.2 header.

    Arguments:
    data -- The data containing the ethernet header information.
    payloadLength -- Length of the data being processed.

    Returns:
    An instance of the 802.2 class
    """
    # Verify minimum IEEE 802.2 LLC header size
    if payloadLength < 3 or len(data) < 3:
        raise ValueError("Packet is too short to contain an LLC header.")
    if len(data) < payloadLength:
        raise ValueError("Packet ends before the 802.3 payload is complete.")

    # Process destination and source service access points
    dsap = data[0]
    ssap = data[1]

    # Process one-byte or two-byte LLC control field
    if data[2] & 0x03 == 0x03:
        control = data[2]
        controlLength = 1
    else:
        if payloadLength < 4 or len(data) < 4:
            raise ValueError("Packet ends before the LLC control field.")
        control = int.from_bytes(data[2:4], "big")
        controlLength = 2

    headerLength = 2 + controlLength
    oui = None
    protocolId = None

    # Process SNAP organization and protocol identifiers
    if dsap == 0xaa and ssap == 0xaa and control == 0x03:
        if payloadLength < 8 or len(data) < 8:
            raise ValueError("Packet ends before the SNAP header is complete.")
        oui = int.from_bytes(data[3:6], "big")
        protocolId = int.from_bytes(data[6:8], "big")
        headerLength = 8

    # Init IEEE 802.2 LLC header
    header = ieee8022Header(
        payloadLength, dsap, ssap, control, controlLength, oui,
        protocolId
    )

    # Remove LLC and SNAP header bytes from byte data
    del data[:headerLength]
    return header


def processIPv4Header(data: list[int]) -> ipv4Header:
    """Processes the IPv4 information.

    Take the data from the input file and return an instance of the
    IPv4 header.

    Arguments:
    data -- The data containing the IPv4 header information.

    Returns:
    An instance of the IPv4 class
    """
    # Verify minimum IPv4 header size
    if len(data) < 20:
        raise ValueError("Packet is too short to contain an IPv4 header.")

    # Process version and internet header length
    version = data[0] >> 4
    ihl = data[0] & 0x0f
    headerLength = ihl * 4

    # Verify IPv4 version and header length
    if version != 4:
        raise ValueError(f"Expected IPv4 version 4, but found {version}.")
    if ihl < 5:
        raise ValueError(f"Invalid IPv4 header length value: {ihl}.")
    if len(data) < headerLength:
        raise ValueError("Packet ends before the IPv4 header is complete.")

    # Process differentiated services and congestion notification
    dscp = data[1] >> 2
    ecn = data[1] & 0x03

    # Process packet length and identification
    totalLength = int.from_bytes(data[2:4], "big")
    identification = int.from_bytes(data[4:6], "big")

    # Process flags and fragment offset
    flagsAndOffset = int.from_bytes(data[6:8], "big")
    flags = flagsAndOffset >> 13
    fragmentOffset = flagsAndOffset & 0x1fff

    # Process time to live, protocol, and header checksum
    ttl = data[8]
    protocol = data[9]
    checksum = int.from_bytes(data[10:12], "big")

    # Process source and destination IP addresses
    source = ".".join(str(byte) for byte in data[12:16])
    destination = ".".join(str(byte) for byte in data[16:20])

    # Process optional header bytes
    options = data[20:headerLength].copy()

    # Init IPv4 header
    header = ipv4Header(
        version, ihl, dscp, ecn, totalLength, identification, flags,
        fragmentOffset, ttl, protocol, checksum, source, destination,
        options
    )

    # Remove IPv4 header from byte data
    del data[:headerLength]
    return header


def processIPv6Header(data: list[int]) -> ipv6Header:
    """Processes the IPv6 information.

    Take the data from the input file and return an instance of the
    IPv6 header.

    Arguments:
    data -- The data containing the IPv6 header information.

    Returns:
    An instance of the IPv6 class
    """
    # Verify minimum IPv6 header size
    if len(data) < 40:
        raise ValueError("Packet is too short to contain an IPv6 header.")

    # Process version, traffic class, and flow label
    version = data[0] >> 4
    trafficClass = ((data[0] & 0x0f) << 4) | (data[1] >> 4)
    flowLabel = ((data[1] & 0x0f) << 16) | int.from_bytes(data[2:4], "big")

    # Verify IPv6 version
    if version != 6:
        raise ValueError(f"Expected IPv6 version 6, but found {version}.")

    # Process payload length, next header, and hop limit
    payloadLength = int.from_bytes(data[4:6], "big")
    nextHeader = data[6]
    hopLimit = data[7]

    # Process source and destination IP addresses
    source = processIPv6Address(data[8:24])
    destination = processIPv6Address(data[24:40])

    # Init IPv6 header
    header = ipv6Header(
        version, trafficClass, flowLabel, payloadLength, nextHeader,
        hopLimit, source, destination
    )

    # Remove IPv6 header from byte data
    del data[:40]
    return header


def processIPv6Address(data: list[int]) -> str:
    """Processes an IPv6 address.

    Take the data from the input file and return a string
    representation of an IPv6 address.

    Arguments:
    data -- The data containing the IPv6 address information.

    Returns:
    A string representation of an IPv6 address
    """
    # Combine each pair of bytes into an IPv6 address section
    sections = list()
    for i in range(0, 16, 2):
        section = (data[i] << 8) | data[i + 1]
        sections.append(format(section, "x"))
    return ":".join(sections)


def processARPHeader(data: list[int]) -> arpHeader:
    """Processes the ARP header information.

    Take the data from the input file and return a class representation
    of the ARP header.

    Arguments:
    data -- The data containing the ARP header information.

    Returns:
    An ARP header class
    """
    # Verify minimum ARP header size
    if len(data) < 8:
        raise ValueError("Packet is too short to contain an ARP header.")

    # Process hardware and protocol types
    hardwareType = int.from_bytes(data[0:2], "big")
    protocolType = int.from_bytes(data[2:4], "big")

    # Process address lengths and operation
    hardwareLength = data[4]
    protocolLength = data[5]
    operation = int.from_bytes(data[6:8], "big")
    headerLength = 8 + (2 * hardwareLength) + (2 * protocolLength)

    # Verify complete ARP header size
    if len(data) < headerLength:
        raise ValueError("Packet ends before the ARP header is complete.")

    # Process sender and target addresses
    index = 8
    senderHardwareBytes = data[index:index + hardwareLength]
    index += hardwareLength
    senderProtocolBytes = data[index:index + protocolLength]
    index += protocolLength
    targetHardwareBytes = data[index:index + hardwareLength]
    index += hardwareLength
    targetProtocolBytes = data[index:index + protocolLength]

    # Format hardware and protocol addresses
    senderHardware = ":".join(
        format(byte, "02x") for byte in senderHardwareBytes
    )
    targetHardware = ":".join(
        format(byte, "02x") for byte in targetHardwareBytes
    )
    senderProtocol = processProtocolAddress(
        senderProtocolBytes, protocolType
    )
    targetProtocol = processProtocolAddress(
        targetProtocolBytes, protocolType
    )

    # Init ARP header
    header = arpHeader(
        hardwareType, protocolType, hardwareLength, protocolLength,
        operation, senderHardware, senderProtocol, targetHardware,
        targetProtocol
    )

    # Remove ARP header from byte data
    del data[:headerLength]
    return header


def processProtocolAddress(data: list[int], protocolType: int) -> str:
    """Processes a protocol address.

    Take the data from the input file and the protocol type as an
    integer and return a string representation of a protocol
    address.

    Arguments:
    data -- The data containing the procol address information.
    protocolType -- The type of protocol being represented.

    Returns:
    A string representation of the protocol address.
    """
    # Format IPv4 addresses in dotted decimal notation
    if protocolType == 0x0800 and len(data) == 4:
        return ".".join(str(byte) for byte in data)
    return " ".join(format(byte, "02x") for byte in data)


def processTCPHeader(data: list[int]) -> tcpHeader:
    """Processes a TCP header.

    Take the data from the input file and return a class representation
    of the TCP header.

    Arguments:
    data -- The data containing the TCP header information.

    Returns:
    A class representation of the TCP header.
    """
    # Verify minimum TCP header size
    if len(data) < 20:
        raise ValueError("Packet is too short to contain a TCP header.")

    # Process source and destination ports
    sourcePort = int.from_bytes(data[0:2], "big")
    destinationPort = int.from_bytes(data[2:4], "big")

    # Process sequence and acknowledgment numbers
    sequenceNumber = int.from_bytes(data[4:8], "big")
    acknowledgmentNumber = int.from_bytes(data[8:12], "big")

    # Process data offset and header length
    dataOffset = data[12] >> 4
    headerLength = dataOffset * 4

    # Verify TCP header length
    if dataOffset < 5:
        raise ValueError(f"Invalid TCP data offset value: {dataOffset}.")
    if len(data) < headerLength:
        raise ValueError("Packet ends before the TCP header is complete.")

    # Process reserved bits and control flags
    reserved = (data[12] >> 1) & 0x07
    flags = ((data[12] & 0x01) << 8) | data[13]

    # Process window, checksum, and urgent pointer
    windowSize = int.from_bytes(data[14:16], "big")
    checksum = int.from_bytes(data[16:18], "big")
    urgentPointer = int.from_bytes(data[18:20], "big")

    # Process optional header bytes
    options = data[20:headerLength].copy()

    # Init TCP header
    header = tcpHeader(
        sourcePort, destinationPort, sequenceNumber,
        acknowledgmentNumber, dataOffset, reserved, flags, windowSize,
        checksum, urgentPointer, options
    )

    # Remove TCP header from byte data
    del data[:headerLength]
    return header



def main(inputFile: str):
    """Given an input file, process the network headers one by one

    Given a text file input, read each network packet into the buffer
    one by one. After parsing, sequentially pop each byte and add it
    to its respective header. Once complete, print out the
    information in an orderly fasion.

    Arguments:
    inputFile -- The path to a txt file to parse.
    """
    messages = list()

    with open(inputFile, "r") as file:
        # Read content
        content = file.read().split("\n")
        message_number = 1

        while(content[message_number*4 - 4]):
            # Process packet description
            packetDescription = content[message_number*4 - 3].strip()
            timestampSeconds = processPacketTimestamp(packetDescription)

            # Parse byte data
            data = content[message_number*4 - 2]    # Second line is byte array
            data = data[1:-1]                       # Crop out prefix and suffix
            data = data.replace(" ", "")            # Remove whitespace
            data = data.split("|")                  # Split data at seperator
            data.remove("0")                        # Remove preamble
            data = list(int(i, 16) for i in data)   # Create list of ints from base-16 strings
            frameLength = len(data)                  # Save original frame size

            # Display packet number and description
            print("=" * 70)
            print(f"Packet {message_number}: {packetDescription}")
            print("=" * 70)

            # Process ethernet header
            ethernetHeader = processEthernetHeader(data)
            print(ethernetHeader)

            # Init remaining packet headers
            ipHeader = None
            tcpHeader = None
            arpPacketHeader = None
            llcHeader = None

            # Process IEEE 802.2 header for length-based frames
            if ethernetHeader.type <= 1500:
                llcHeader = processIEEE8022Header(
                    data, ethernetHeader.type
                )
                print(llcHeader)

            # Process IPv4 header for IPv4 packets
            elif ethernetHeader.type == 0x0800:
                ipHeader = processIPv4Header(data)
                print(ipHeader)

                # Process TCP header for TCP packets
                if ipHeader.protocol == 6 and ipHeader.fragmentOffset == 0:
                    tcpHeader = processTCPHeader(data)
                    tcpHeader.src_ip = ipHeader.source
                    tcpHeader.dest_ip = ipHeader.destination
                    print(tcpHeader)

            # Process ARP header for ARP packets
            elif ethernetHeader.type == 0x0806:
                arpPacketHeader = processARPHeader(data)
                print(arpPacketHeader)

            # Process IPv6 header for IPv6 packets
            elif ethernetHeader.type == 0x86dd:
                ipHeader = processIPv6Header(data)
                print(ipHeader)

                # Process TCP header when it directly follows IPv6
                if ipHeader.nextHeader == 6:
                    tcpHeader = processTCPHeader(data)
                    print(tcpHeader)
            else:
                print("Unsupported Ethernet frame type.")

            # Separate each packet with three blank lines
            print("\n\n\n", end="")

            # Add message to list
            messages.append(message(
                ethernetHeader, ipHeader, tcpHeader, arpPacketHeader,
                llcHeader, message_number, packetDescription,
                timestampSeconds, frameLength
            ))

            # Incrament to next message
            message_number+=1

    print(formatStatisticsReport(messages))
    return messages



if __name__=="__main__":
    # Process a number conversion request
    if len(sys.argv) == 3 and sys.argv[1] == "--convert":
        try:
            print(formatConversion(sys.argv[2]))
        except ValueError as error:
            print(f"Error: {error}")
            raise SystemExit(1)

    # Process a packet input file
    elif len(sys.argv) == 2 and sys.argv[1] != "--convert":
        try:
            main(sys.argv[1])
        except FileNotFoundError:
            print(f'Error: File "{sys.argv[1]}" was not found.')
            raise SystemExit(1)
        except PermissionError:
            print(f'Error: Permission denied for file "{sys.argv[1]}".')
            raise SystemExit(1)
        except OSError as error:
            print(f'Error: Could not read file "{sys.argv[1]}": {error}')
            raise SystemExit(1)

    # Display usage when the arguments do not match either operation
    else:
        print(f"Usage: python3 {sys.argv[0]} <input_file>")
        print(f"       python3 {sys.argv[0]} --convert <number>")
        print(f"Example: python3 {sys.argv[0]} input.txt")
        print(f"         python3 {sys.argv[0]} --convert 0x002a")
        raise SystemExit(1)