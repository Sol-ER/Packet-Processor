# CSCI.351.01 - Data Comm & Networks
# Programming Part 1
# George Scheper, Ethan Ricker, Ricky Leung

class ethernetIIHeader:
    def __init__(self, dst:str, src:str, type:int):
        self.etherdst = dst
        self.ethersrc = src
        self.type = type

    def __str__(self):
        return f"destination: {self.etherdst}\tsource: {self.ethersrc}\ttype: {self.getEtherType()}"

    def getEtherType(self) -> str:
        typeHex = hex(self.type)
        if (typeHex == "0x800"): return "IPv4"
        elif (typeHex == "0x806"): return "ARP"
        elif (typeHex == "0x86dd"): return "IPv6"
        return f"type \"{typeHex}\" not listed"



class ipv4Header:
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

    def __str__(self) -> str:
        options = "None"
        if self.options:
            options = " ".join(format(byte, "02x") for byte in self.options)

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
            f"  Options:              {options}"
        )


class ipv6Header:
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


class tcpHeader:
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

    def getFlags(self) -> str:
        flagNames = (
            (0x100, "NS"), (0x080, "CWR"), (0x040, "ECE"),
            (0x020, "URG"), (0x010, "ACK"), (0x008, "PSH"),
            (0x004, "RST"), (0x002, "SYN"), (0x001, "FIN")
        )
        enabled = [name for mask, name in flagNames if self.flags & mask]
        return ", ".join(enabled) if enabled else "None"

    def __str__(self) -> str:
        options = "None"
        if self.options:
            options = " ".join(format(byte, "02x") for byte in self.options)

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
            f"  Options:              {options}"
        )


class message:
    def __init__(self, ethernetHeader: ethernetIIHeader, ipHeader=None,
                 tcpHeader=None, arpHeader=None):
        self.ethernetHeader = ethernetHeader
        self.ipHeader = ipHeader
        self.tcpHeader = tcpHeader
        self.arpHeader = arpHeader



def processEthernetHeader(data:list[int]):
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


def processIPv4Header(data: list[int]) -> ipv4Header:
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
    # Combine each pair of bytes into an IPv6 address section
    sections = list()
    for i in range(0, 16, 2):
        section = (data[i] << 8) | data[i + 1]
        sections.append(format(section, "x"))
    return ":".join(sections)


def processARPHeader(data: list[int]) -> arpHeader:
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
    # Format IPv4 addresses in dotted decimal notation
    if protocolType == 0x0800 and len(data) == 4:
        return ".".join(str(byte) for byte in data)
    return " ".join(format(byte, "02x") for byte in data)


def processTCPHeader(data: list[int]) -> tcpHeader:
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



def main():
    messages = list()

    with open("input.txt", "r") as file:
        # Read content
        content = file.read().split("\n")
        message_number = 1

        while(content[message_number*4 - 4]):
            # Parse byte data
            data = content[message_number*4 - 2]    # Second line is byte array
            data = data[1:-1]                       # Crop out prefix and suffix
            data = data.replace(" ", "")            # Remove whitespace
            data = data.split("|")                  # Split data at seperator
            data.remove("0")                        # Remove preamble
            data = list(int(i, 16) for i in data)   # Create list of ints from base-16 strings

            # Process ethernet header
            ethernetHeader = processEthernetHeader(data)
            print(ethernetHeader)

            # Process IPv4 header for IPv4 packets
            ipHeader = None
            tcpHeader = None
            arpPacketHeader = None
            if ethernetHeader.type == 0x0800:
                ipHeader = processIPv4Header(data)
                print(ipHeader)

                # Process TCP header for TCP packets
                if ipHeader.protocol == 6 and ipHeader.fragmentOffset == 0:
                    tcpHeader = processTCPHeader(data)
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

            print()

            # Add message to list
            messages.append(message(
                ethernetHeader, ipHeader, tcpHeader, arpPacketHeader
            ))

            # Incrament to next message
            message_number+=1



if __name__=="__main__":
    main()
