import socket
import struct
from struct import *
import sys
import textwrap
import matplotlib.pyplot as plt
import numpy as np

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype)
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data


# return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpack IPV4 packet
# the data in the argument is the payload part of the ethernet packet
def ipv4_packet(data):
    version_and_header_length = data[0]
    version = version_and_header_length >> 4  # shift it to right by 4 to get the version
    header_length = (version_and_header_length & 15) * 4

    tos, total_length, identification, flags_frag_offset, ttl, proto, header_checksum, src_addr, target_addr = struct.unpack(
        '! B H H H B B H 4s 4s', data[1:20])
    flags = flags_frag_offset
    x_flag = flags & (2 ** 15) >> 15
    d_flag = flags & (2 ** 14) >> 14
    m_flag = flags & (2 ** 13) >> 13
    frag_offset = flags_frag_offset & (2 ** 13 - 1)
    # ttl, proto, src_addr, target_addr = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ipv4_addr(src_addr), get_ipv4_addr(target_addr), data[
                                                                                                    header_length:], total_length, identification, d_flag, m_flag, frag_offset


# a function to get IPV4 format address
def get_ipv4_addr(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packets - if protocol = 1
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment - if protocol = 6
def tcp_segment(data):
    src_port, dest_port, seqnum, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, seqnum, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[
                                                                                                                     offset:]


# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# format multi line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def save_to_file():
    f = open("report.txt", "w+")
    # write the total number of packets of each protocol to report file
    f.write("Packet Protocol Report : ")
    f.write("------------------------------\n")
    f.write("\nTotal Packets Captured: {}\nTCP Packets: {}, UDP Packets: {}, ICMP Packets: {}, Other: {}\n".format(
        total_packet_num,
        total_tcp_num,
        total_udp_num,
        total_icmp_num, total_other_num))
    # writing the source ip of packet - decreasing order to report file
    f.write("\nPacket Length Report :\n ")
    f.write("------------------------------\n")
    for x in reversed(ip_and_packet_num):
        if x[0] == "first":
            continue
        else:
            f.write("Source: {}   | {} packets\n".format(x[0], x[1]))

    # write the max , min and average packet size to report file
    max_packet_size = max(all_packet_size)
    min_packet_size = min(all_packet_size)
    average_packet_size = sum(all_packet_size) / len(all_packet_size)
    f.write("\nPacket Length Report : \n")
    f.write("------------------------------\n")
    f.write("\nMaximum packet length: {}, Minimum packet length: {}, Average packet length: {}\n".format(max_packet_size,
                                                                                                       min_packet_size,
                                                                                                       average_packet_size))
    # write the number of the fragmented packets to file
    f.write("\nPacket Fragmentation Report :\n")
    f.write("------------------------------\n")
    f.write("\nNumber of fragmented packets: {}\n".format(fragmented_packets_num))
    # write extra information to file
    f.write("\nExtra Report : \n")
    f.write("------------------------------\n")
    f.write("The number of HTTP requests: {}\n".format(total_http_num))
    f.write("The number of DNS requests: {}\n".format(total_dns_num))
    f.write("\nPort Usage Report : \n")
    f.write("------------------------------\n")
    for x in reversed(used_ports):
        if x[0] == "first_port":
            continue
        else:
            f.write("Port: {}   | {} packets\n".format(x[0], x[1]))


def sort_by_number_of_packets(ip_list, ip):
    if type(ip_list) is None:
        return
    else:
        for i in range(len(ip_list)):
            if ip in ip_list[i]:
                y = list(ip_list[i])
                y[1] += 1
                ip_list[i] = tuple(y)
                return
        new_t = (ip, 1)
        ip_list.append(new_t)
        # ip_list.sort(key=lambda x: x[1])


def sort_port_by_packet_num(port_list, new_port):
    if type(port_list) is None:
        return
    else:
        for i in range(len(port_list)):
            if new_port in port_list[i]:
                y = list(port_list[i])
                y[1] += 1
                port_list[i] = tuple(y)
                return
        new_t = (new_port, 1)
        port_list.append(new_t)


def check_fragmentation(frag_list, src, id):
    if type(frag_list) is None:
        return False
    else:
        current_t = (src, id)
        for i in range(len(frag_list)):
            if frag_list[i] == current_t:
                return False  # don't increment the fragmented num - already counted as fragmented packets
            else:
                frag_list.append(current_t)
                return True


def draw_pie_chart():
    fig, ax = plt.subplots(figsize=(6, 3), subplot_kw=dict(aspect="equal"))

    recipe = ["TCP"]

    data = [total_tcp_num]
    if total_udp_num != 0:
        recipe.append("UDP")
        data.append(total_udp_num)
    if total_icmp_num != 0:
        recipe.append("ICMP")
        data.append(total_icmp_num)
    if total_other_num != 0:
        recipe.append("OTHER")
        data.append(total_other_num)

    wedges, texts = ax.pie(data, wedgeprops=dict(width=0.5), startangle=-40)

    bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
    kw = dict(arrowprops=dict(arrowstyle="-"),
              bbox=bbox_props, zorder=0, va="center")

    for i, p in enumerate(wedges):
        ang = (p.theta2 - p.theta1) / 2. + p.theta1
        y = np.sin(np.deg2rad(ang))
        x = np.cos(np.deg2rad(ang))
        horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
        connectionstyle = "angle,angleA=0,angleB={}".format(ang)
        kw["arrowprops"].update({"connectionstyle": connectionstyle})
        ax.annotate(recipe[i], xy=(x, y), xytext=(1.35 * np.sign(x), 1.4 * y),
                    horizontalalignment=horizontalalignment, **kw)

    ax.set_title("Captured Packets")
    plt.show()


def show_simple_pie_chart():
    labels = ['TCP', 'UDP', 'ICMP', 'OTHER']
    sizes = [total_tcp_num, total_udp_num, total_icmp_num, total_other_num]
    colors = ['yellowgreen', 'gold', 'lightskyblue', 'lightcoral']

    patches, texts = plt.pie(sizes, colors=colors, shadow=False, startangle=90)
    plt.legend(patches, labels, loc="best")
    plt.axis('equal')
    plt.title('Captured Packets')
    plt.tight_layout()
    plt.show()


def pie_chart_percentage():
    labels = 'TCP', 'UDP', 'ICMP', 'OTHER'
    sizes = [total_tcp_num, total_udp_num, total_icmp_num, total_other_num]
    explode = (0, 0, 0, 0.1)  # only "explode" the 2nd slice (i.e. 'Hogs')

    fig1, ax1 = plt.subplots()
    ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%',
            shadow=False, startangle=90)
    ax1.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.

    plt.show()


if __name__ == '__main__':
    print("This is a packet sniffer program")
    print("Enter 0 to exit")
    print("Enter 1 to start Packet Sniffing")
    inp = input(">>> ")
    inp = int(inp)
    if inp == 0:
        print("See you later !")
    elif inp == 1:
        global total_packet_num
        total_packet_num = 0

        global total_tcp_num
        total_tcp_num = 0

        global total_udp_num
        total_udp_num = 0

        global total_icmp_num
        total_icmp_num = 0

        global total_other_num
        total_other_num = 0

        global ip_and_packet_num
        ip_and_packet_num = []
        ip_and_packet_num.append(("first", 0))

        global all_packet_size
        all_packet_size = []

        global total_http_num
        total_http_num = 0

        global total_dns_num
        total_dns_num = 0

        global fragmented_packets_num
        fragmented_packets_num = 0

        global fragmented_packet_data
        fragmented_packet_data = []
        fragmented_packet_data.append(("first", -1))

        global used_ports
        used_ports = []
        used_ports.append(("first_port", -1))
        # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

        while True:
            try:
                raw_data, addr = s.recvfrom(65535)
                total_packet_num += 1
                dest_mac, src_mac, eth_proto, data = ethernet_head(raw_data)
                print('\nEthernet Frame:')
                print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

                if eth_proto == 8:  # ipv4
                    version, header_length, ttl, proto, src, target, data, total_length, identification, d_flag, m_flag, frag_offset = ipv4_packet(
                        data)
                    # save src ip in a tuple
                    sort_by_number_of_packets(ip_and_packet_num, src)

                    # save the size of new packet in a list
                    current_packet_size = total_length
                    all_packet_size.append(current_packet_size)

                    # count the number of fragmented packets
                    if m_flag == 1 or (m_flag == 0 and frag_offset > 0):
                        if check_fragmentation(fragmented_packet_data, src, identification):
                            fragmented_packets_num += 1

                    print(TAB_1 + 'IPv4Packet : ')
                    print(
                        TAB_2 + 'Identification: {}, D Flag: {}, M Flag: {}, Offset: {}'.format(identification, d_flag,
                                                                                                m_flag, frag_offset))
                    print(
                        TAB_2 + 'Total Length: {},Version: {}, Header Length: {}, TTL: {}'.format(total_length, version,
                                                                                                  header_length, ttl))
                    print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                    if proto == 1:  # ICMP
                        total_icmp_num += 1
                        icmp_type, code, checksum, data = icmp_packet(data)
                        print(TAB_1 + 'ICMP Packet : ')
                        print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                        print(TAB_2 + 'Data: ')
                        print(format_multi_line(DATA_TAB_3, data))

                    elif proto == 6:  # TCP
                        total_tcp_num += 1
                        src_port, dest_port, seqnum, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(
                            data)
                        sort_port_by_packet_num(used_ports, src_port)
                        sort_port_by_packet_num(used_ports, dest_port)
                        if src_port == 80 or dest_port == 80:
                            total_http_num += 1
                        print(TAB_1 + 'TCP Segment: ')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                        print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(seqnum, acknowledgement))
                        print(TAB_2 + 'Flags: ')
                        print(
                            TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack,
                                                                                                  flag_psh,
                                                                                                  flag_rst, flag_syn,
                                                                                                  flag_fin))
                        print(TAB_2 + 'Data: ')
                        print(format_multi_line(DATA_TAB_3, data))

                    elif proto == 17:  # UDP
                        total_udp_num += 1
                        src_port, dest_port, size, data = udp_segment(data)
                        # port check
                        sort_port_by_packet_num(used_ports, src_port)
                        sort_port_by_packet_num(used_ports, dest_port)
                        # dns check
                        if src_port == 53 or dest_port == 53:
                            total_dns_num += 1
                        print(TAB_1 + 'UDP Segment : ')
                        print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port,
                                                                                                 size))

                    else:
                        total_other_num += 1
                        print('Data: ')
                        print(format_multi_line(DATA_TAB_1, data))
                else:
                    total_other_num += 1
                    print('Ethernet Data:')
                    print(format_multi_line(DATA_TAB_1, data))
            except KeyboardInterrupt:
                print("\n...Exiting Sniffer.....")
                ip_and_packet_num.sort(key=lambda x: x[1])
                used_ports.sort(key=lambda x: x[1])

                save_to_file()
                print("See the captured packets Graph")
                print("0 - A simple pie chart")
                print("1 - A donat shaped pie chart")
                print("2 - A simple pie chart with percentage")
                inp = input()
                inp = int(inp)
                if inp == 0:
                    show_simple_pie_chart()
                elif inp == 1:
                    draw_pie_chart()
                elif inp == 2:
                    pie_chart_percentage()
                print("Report file updated...")
                sys.exit(0)
        s.close()
