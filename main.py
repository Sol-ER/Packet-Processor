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
                 tcpHeader=None):
        self.ethernetHeader = ethernetHeader
        self.ipHeader = ipHeader
        self.tcpHeader = tcpHeader



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
            if ethernetHeader.type == 0x0800:
                ipHeader = processIPv4Header(data)
                print(ipHeader)

                # Process TCP header for TCP packets
                if ipHeader.protocol == 6 and ipHeader.fragmentOffset == 0:
                    tcpHeader = processTCPHeader(data)
                    print(tcpHeader)
            else:
                # NOTE: double check if IPv6 and ARP packets need to be processed
                print("IPv4 and TCP processing skipped for this frame.")

            print()

            # Add message to list
            messages.append(message(ethernetHeader, ipHeader, tcpHeader))

            # Incrament to next message
            message_number+=1



if __name__=="__main__":
    main()
