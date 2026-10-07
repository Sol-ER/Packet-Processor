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



class message:
    def __init__(self, ethernetHeader:ethernetIIHeader):
        self.ethernetHeader = ethernetHeader



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

            # Add message to list
            messages.append(message(ethernetHeader))

            # Incrament to next message
            message_number+=1



if __name__=="__main__":
    main()