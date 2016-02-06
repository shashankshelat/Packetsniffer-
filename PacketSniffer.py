import socket
import struct
import binascii
import socket, sys
from struct import *
import time
import datetime
from scapy import *
from scapy.error import Scapy_Exception
import numpy as np
import matplotlib.pyplot as plt
import numpy


modArray = []
timearray = []
rws = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

def ethAddr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b

try:
    while True:
        p = rws.recvfrom(65565)
        ethHead = p[0][0:14]
        ethDetails = struct.unpack("!6s6s2s", ethHead)
        arpHeader = p[0][14:42]
        arpDetails = struct.unpack("2s2s1s1s2s6s4s6s4s", arpHeader)
        Type = ethDetails[2]

        if Type == '\x08\x06':
            print "****************ETHERNET_FRAME_****************"
            print "Dest MAC:        ", binascii.hexlify(ethDetails[0])
            print "Source MAC:      ", binascii.hexlify(ethDetails[1])
            print "Type:            ", binascii.hexlify(Type)
            print "************************************************"
            print "******************_ARP_HEADER_******************"
            print "Protocol type: ", binascii.hexlify(arpDetails[1])
            print "Hardware size: ", binascii.hexlify(arpDetails[2])
            print "Protocol size: ", binascii.hexlify(arpDetails[3])
            print "Opcode:          ", binascii.hexlify(arpDetails[4])
            print "Source MAC:      ", binascii.hexlify(arpDetails[5])
            print "Source IP:       ", socket.inet_ntoa(arpDetails[6])
            print "Dest MAC:        ", binascii.hexlify(arpDetails[7])
            print "Dest IP:         ", socket.inet_ntoa(arpDetails[8])
            print "*************************************************\n"


        elif Type == '\x08\x00':
            p = p[0]
            Length = 14
            ethHeader = p[:Length]
            eth = unpack('!6s6sH' , ethHeader)
            proto  = socket.ntohs(eth[2])
            print "****************ETHERNET_FRAME_****************"
            print 'Destination MAC : ' + ethAddr(p[0:6])
            print ' Source MAC : ' + ethAddr(p[6:12])
            print ' Protocol : ' + str(proto )
            print "****************ETHERNET_FRAME_****************"
            if proto  == 8 :
                ipHeader = p[Length:20+Length]
                iph = unpack('!BBHHHBBH4s4s' , ipHeader)
                version_ihl = iph[0]
                version = version_ihl >> 4
                ihl = version_ihl & 0xF
                ipLength = ihl * 4
                ttl = iph[5]

                abc = []
                abc.append(ttl)

                protocol = iph[6]
                sourceaddress = socket.inet_ntoa(iph[8]);
                destinationaddress = socket.inet_ntoa(iph[9]);
                print "****************ETHERNET_FRAME_****************"
                print 'Version : ' + str(version)
                print ' IP Header Length : ' + str(ihl)
                print ' TTL : ' + str(ttl)
                print ' Protocol : ' + str(protocol)
                print ' Source Address : ' + str(sourceaddress)
                print ' Destination Address : ' + str(destinationaddress)
                print "****************ETHERNET_FRAME_****************"
                if protocol == 6 :
                    t = ipLength + Length
                    tcpHeader = p[t:t+20]
                    tcph = unpack('!HHLLBBHHH' , tcpHeader)
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    sequence = tcph[2]
                    acknowledgement = tcph[3]
                    shift = tcph[4]
                    tcpHLenth = shift >> 4
                    TotalLength = iph[2]

                    print "****************-----TCP------****************"
                    print 'Source Port : ' + str(source_port)
                    print ' Dest Port : ' + str(dest_port)
                    print  ' Sequence Number : ' + str(sequence)
                    print   ' Acknowledgement : ' + str(acknowledgement)
                    print    ' TCP header length : ' + str(tcpHLenth)
                    print 'Total Length : ' + str(TotalLength)
                    print "****************------TCP-----****************"

                    HeaderSize = Length + ipLength + tcpHLenth * 4
                    data_size = len(p) - HeaderSize

                    a = len(p)
                    cde = []
                    cde.append(a)

                    data = p[HeaderSize:]
                    print 'Data : ' + data
                    MSS = TotalLength - (tcpHLenth + ihl)
                    print MSS

                    start=time.time()
                    elapsed = time.time() - start
                    print 'RTT calculated is:' + str(elapsed) + " seconds"

                    if elapsed > 0 :
                        throughput = MSS / elapsed
                        print throughput

                        modArray.append(throughput)
                    timenow = datetime.datetime.now()

                    timearray.append(timenow)
                    c = max(abc)
                    d = numpy.mean(abc)
                    print ' Diameter of the Network : '+ str(c)
                    print 'Average :' + str(d)

                    e = numpy.mean(cde)
                    print 'Avg Packet Size :' + str(e)

                elif protocol == 1 :
                    u = ipLength + Length
                    icmph_length = 4
                    icmp_header = p[u:u+4]
                    icmph = unpack('!BBH' , icmp_header)
                    icmp_type = icmph[0]
                    code = icmph[1]
                    checksum = icmph[2]

                    print "****************-----ICMP-----****************"
                    print 'Type : ' + str(icmp_type)
                    print ' Code : ' + str(code)
                    print ' Checksum : ' + str(checksum)
                    print "****************-----ICMP-----****************"

                    HeaderSize = Length + ipLength + icmph_length
                    data_size = len(p) - HeaderSize
                    data = p[HeaderSize:]
                    print 'Data : ' + data

                elif protocol == 17 :
                    u = ipLength + Length
                    udph_length = 8
                    udp_header = p[u:u+8]
                    udph = unpack('!HHHH' , udp_header)
                    source_port = udph[0]
                    dest_port = udph[1]
                    length = udph[2]
                    checksum = udph[3]

                    print "****************----UDP----****************"
                    print 'Source Port : ' + str(source_port)
                    print ' Dest Port : ' + str(dest_port)
                    print ' Length : ' + str(length)
                    print ' Checksum : ' + str(checksum)
                    print "****************----UDP----****************"


                    HeaderSize = Length + ipLength + udph_length
                    data_size = len(p) - HeaderSize
                    data = p[HeaderSize:]
                    print 'Data : ' + data
                print

except KeyboardInterrupt:

        x = modArray
        y = timearray
        plt.plot(x, y, 'r')

        plt.show()

