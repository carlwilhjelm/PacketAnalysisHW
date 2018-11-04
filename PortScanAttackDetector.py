from scapy.all import *
import sys

# uncomment method call in code below for pretty print of TCP packets during iteration
def printDetails(p):
    # print(p.summary())
    # print(p.show())
    print(total)
    if p.haslayer('TCP'):
        layer = 'TCP'
        if p.haslayer('IP'):
            print("IP source = " + p['IP'].src)
            print("IP destination = " + p['IP'].dst)
        print(layer + " flags = " + str(p[layer].flags))
        print("MAC source = " + p.src)
        print("Source Port = " + str(p[layer].sport))
        print("MAC destination = " + p.dst)
        print("Destination Port = " + str(p[layer].dport))
    elif p.haslayer('UDP'):
        layer = 'UDP'
        if p.haslayer('IP'):
            print("IP source = " + p['IP'].src)
            print("IP destination = " + p['IP'].dst)
        print("MAC source = " + p.src)
        print("Source Port = " + str(p[layer].sport))
        print("MAC destination = " + p.dst)
        print("Destination Port = " + str(p[layer].dport))
    else:
        print("PACKET NOT TCP NOR UDP")
    print()
    return


# takes file path as argument
portscanFile = sys.argv[1]
psData = rdpcap(portscanFile)

total = 0
outlyerCount = 0
portscanDict = {}

# iterate through every packet
for packet in psData:
    total += 1
    # if the packet has a tcp layer and a SYN flag
    if packet.haslayer('TCP') and packet.haslayer('IP') and str(packet['TCP'].flags) is 'S':
        #printDetails(packet)
        packetSourceIP = packet['IP'].src
        # if the packet's source IP has not previously been entered into the dictionary
        # add it as a new key with an empty list as its value
        if packetSourceIP not in portscanDict:
            portscanDict[packetSourceIP] = []
        # append the destination port to the source IP key of the portscan dictionary
        portscanDict[packetSourceIP].append(packet['TCP'].dport)

    # if the packet has a udp layer and a destination port
    elif packet.haslayer('UDP') and packet.haslayer('IP') and packet['UDP'].dport:
        #printDetails(packet)
        packetSourceIP = packet['IP'].src
        # if the packet's source IP has not previously been entered into the dictionary
        # add it as a new key with an empty list as its value
        if packetSourceIP not in portscanDict:
            portscanDict[packetSourceIP] = []
        # append the destination port to the source IP key of the portscan dictionary
        portscanDict[packetSourceIP].append(packet['UDP'].dport)

    else:
        outlyerCount += 1

print("Total Packets = " + str(total))
print("Total Outlyers = " + str(outlyerCount))
print()
portScanIPCount = 0
for ip in portscanDict:
    if len(portscanDict[ip]) >= 100:
        portScanIPCount += 1
        print("Port attempts from " + ip + " = " + str(len(portscanDict[ip])))
print()
print("Total IPs doing portscan attacks = " + str(portScanIPCount))