from scapy.all import *

# uncomment method call in code below for pretty print of ARP packets during iteration
def printDetails(p):
    # print(p.summary())
    # print("Source: IP=" + p.psrc + "\tMAC=" + p.src)
    # print("Destination: IP=" + p.pdst + "\tMAC=" + p.hwdst)
    # print(p.op)
    # print(p.show())
    # print()
    return

# takes file path as argument
spoofFile = sys.argv[1]
spoofData = rdpcap(spoofFile)

total = 0
arpCount = 0
whoHasDict = {}
spooferPackets = []

# iterate through every packet
for packet in spoofData:
    total += 1
    # only consider packets with an ARP layer and
    # look for attempts to overwrite initial response to 'who-has' requests
    if packet.haslayer('ARP'):
        arpCount += 1
        # uncomment lines below to print details for packets
        # print(total)
        # printDetails(packet)

        # if this packet is a 'who-has' request (packet.op == 1),
        # initialize dictionary value of destination IP (of request) to 'none'
        if packet.op == 1:
            whoHasDict[packet.pdst] = 'none'
        # if this packet is an 'is-at' (packet.op == 2) response
        elif packet.op == 2:
            # if a request was made for a MAC address for the same IP as the source of this packet
            if packet.psrc in whoHasDict:
                # if this is the first response to that request
                if whoHasDict[packet.psrc] is 'none':
                    # overwrite dictionary value at this packet's source IP to this packet's MAC address
                    whoHasDict[packet.psrc] = packet.hwdst
                # otherwise this packet is attempting to overwrite the original response
                # log a spoof
                else:
                    spooferPackets.append(total)

print("Total = " + str(total))
print("Total ARP packets = " + str(arpCount))

print("Spoofer Packets = ", end= '')
# print the spoofers in a readable way
for i in range(len(spooferPackets)):
    if i % 10 == 0: print()
    print(str(spooferPackets[i]), end=' ')

