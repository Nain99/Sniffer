import socket
import struct

def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def ethernet_head(raw_data):

    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])

    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data 

def icmp_head(raw_data):
    packet_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    data = raw_data[4:]
    return packet_type, code, checksum, data 

def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src = get_ip(src)
    target = get_ip(target)
    data = raw_data[header_length:]
    return version_header_length, version, header_length, ttl, proto, src, target, data

def ipv42_head(raw_data):
    ipheader = struct.unpack('!BBHHHBBH4s4s',raw_data[:20])
    #TOS = str(ipheader[1])
    IP_Total_Length = str(ipheader[2])
    ID = ipheader[3]
    TOS = ipheader[1] >> 5
    Checksum = str(ipheader[7])
    return IP_Total_Length, ID , TOS ,Checksum

def get_ip(addr):
    return '.'.join(map(str, addr))

def tcp_head( raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(
        '! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    data = raw_data[offset:]
    tcpheader = struct.unpack('!HHLLBBHHH',raw_data[:20])
    window = tcpheader[6];
    checksum = tcpheader[7];
    Urgent_Pointer = tcpheader[8];
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window , checksum , Urgent_Pointer, offset

def udp_head(raw_data):
    udpheader = struct.unpack('! H H H H', raw_data[:8])
    src_port = str(udpheader[0])
    dest_port = str(udpheader[1])
    length = str(udpheader[2])
    checksum = str(udpheader[3])
    return src_port, dest_port, length, checksum 

def main():
    s  = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        print('----------------------------------------------------')
        print('Perez Uria Nain Adalid CI: 6932070')
        #ETHERNET
        print('\nEthernet Header:')
        print('|-Destination Address:\t', eth[0])
        print('|-Source Address:\t', eth[1])
        print('|-Protocol:\t\t', eth[2])
        if eth[2] == 8:
            #IP
            ipv4 = ipv4_head(eth[3])
            ipv42 = ipv42_head(eth[3])
            print('\nIP Header:')
            print('|-IP Version:\t\t',ipv4[1])
            print('|-IP Header Length: \t',ipv4[2])
            print('|-Type of Service:\t',ipv42[2])
            print('|-IP Total Length:\t',str(ipv42[0]))
            print('|-Identification:\t',ipv42[1])
            print('|-TTL:\t\t\t',ipv4[3])
            print('|-Protocol:\t\t',ipv4[4])
            print('|-Checksum:\t\t', str(ipv42[3]))
            print('|-Source IP:\t\t',ipv4[5])
            print('|-Destination IP:\t',ipv4[6])

            # TCP
            if ipv4[4] == 6:
                tcp = tcp_head(ipv4[7])
                print('\nTCP Header:')
                print('|-Source Port:\t\t',tcp[0])
                print('|-Destination Port:\t',tcp[1])
                print('|-Sequence Number:\t',tcp[2])
                print('|-Acknowledgment Number: ',tcp[3])
                print('|-Header Length:\t',tcp[13])
                print('|-Urgent Flag:\t\t',tcp[4])
                print('|-Acknowledgement Flag:\t',tcp[5])
                print('|-Push Flag:\t\t',tcp[6])
                print('|-Reset Flag:\t\t',tcp[7])
                print('|-Synchronise Flag:\t',tcp[8])
                print('|-Finish Flag:\t\t',tcp[9])
                print('|-Window:\t\t',tcp[10])
                print('|-Checksum:\t\t',tcp[11])
                print('|-Urgent Pinter:\t', tcp[12])
            # ICMP
            elif ipv4[4] == 1:
                icmp = icmp_head(ipv4[7])
                print('\nICMP Header:')
                print('|-Type:\t\t\t',icmp[0])
                print('|-Code:\t\t\t',icmp[1])
                print('|-Checksum:\t\t',icmp[2])
            elif ipv4[4] == 17:
                udp = udp_head(ipv4[7])
                print('\nUDP Header:')
                print('|-Source Port:\t\t',udp[0])
                print('|-Destination Port:\t',udp[1])
                print('|-Length:\t\t',udp[2])
                print('|-Checksum:\t\t',udp[3])
        print('----------------------------------------------------')
main()
