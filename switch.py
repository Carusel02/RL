#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

ports = {} # ports of the switch

def parse_config_file(switch_id):
    # Implementation of the parse_config_file function
    file_path = 'configs/switch{}.cfg'.format(switch_id)
    print("[CONFIG FILE] READ : {}".format(file_path))

    with open(file_path) as file:
       file_content = file.read()

    # Parse the config file and set the switch parameters
    
    # Split the content into lines
    lines = file_content.split('\n')

    # Extract information from the first line
    dpid = lines[0]
    print("[PRIO] SWITCH : {}".format(dpid))

    switches_info = [line.split() for line in lines[1:] if line]
    
    for switch_info in switches_info:
        print("[PORT] SWITCH : {}".format(switch_info))
        interface_name = switch_info[0]
        port = switch_info[1]
        ports[interface_name] = port

    print("[ALL] PORTS : {}".format(ports))



def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

########################################################################

MAC_Table = {}  # Initialize an empty MAC table

def forward_frame(data, length, output_interface):
    send_to_link(output_interface, data, length)

def is_unicast(mac):
    dest_mac_bytes = mac.split(':')
    first_byte = int(dest_mac_bytes[0], 16)
    return (first_byte & 1) == 0

def print_mac_table():
    # Implementation of the print_mac_table function
    print("MAC Table:")
    for key, value in MAC_Table.items():
        print(key, ":", value)
    print("\n")
    

########################################################################

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    print("######################## LOAD INFO ########################")
    print("[ID] SWITCH ID : {}".format(switch_id))
    parse_config_file(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("[INFO] START SWITCH ID {}".format(switch_id), flush=True)
    print("[INFO] SWITCH MAC : ", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Printing interface names
    for i in interfaces:
        print("[INTERFACE] INTERFACE {} HAS NAME {}".format(i, get_interface_name(i)))
    print("######################## END INFO ########################\n")

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].


        interface, data, length = recv_from_any_link()
        print("\n\n*************** PACKET RECEIVED ***************\n")
        print("[INFO] Received frame of size {} on interface {} ({})\n".format(length, interface, get_interface_name(interface)), flush=True)
        # interface source = interface
        # print("[VLAN] INTERFACE PACKET {} ({}) HAS VLAN ID : {}".format(interface, get_interface_name(interface), ports[get_interface_name(interface)]))

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]
        untagged_frame = tagged_frame[0:12] + tagged_frame[16:]

        print(f'[DESTINATION MAC] Destination MAC: {dest_mac}')
        print(f'[SOURCE MAC] Source MAC: {src_mac}')
        print(f'[ETHERTYPE] EtherType: {ethertype}')
        print(f'[DEFAULT VLAN ID] Vlan ID: {vlan_id}\n')


        # TODO: Implement forwarding with learning

        MAC_Table[src_mac] = interface
        

        # we have a UNICAST FRAME and WE KNOW WHERE TO SEND it
        if is_unicast(dest_mac) and dest_mac in MAC_Table:
            # UNICAST ROUTE (send to a specific target)
            
            print("[ROUTE UNICAST -> SEND ON INTERFACE {} ({})]".format(MAC_Table[dest_mac], get_interface_name(MAC_Table[dest_mac])))

            vlan_id_received = ports[get_interface_name(interface)]
            print("[VLAN ID SOURCE] Vlan ID : {}".format(vlan_id_received))
            vlan_id_destination = ports[get_interface_name(MAC_Table[dest_mac])] 
            print("[VLAN ID DESTINATION] Vlan ID : {}".format(vlan_id_destination))
            
            # ACCES
            if vlan_id_received != 'T' :
                print("SOURCE ACCES -> ", end='')
                # -> TRUNK
                if vlan_id_destination == 'T':
                    print("DESTINATION TRUNK\n")
                    # ADD HEADER
                    header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
                    forward_frame(header_data, length + 4, MAC_Table[dest_mac]) 
                # -> ACCES
                else:
                    print("DESTINATION ACCES -> ", end='')
                # HAVE THE SAME VLAN ID
                    if vlan_id_destination == vlan_id_received:
                        print("[SUCCES] Same Vlan ID...\n")
                        forward_frame(data, length, MAC_Table[dest_mac])
                    else:
                        print("[FAIL] Mismatch Vlan ID...\n")
            

            # TRUNK
            if vlan_id_received == 'T':
                print("SOURCE TRUNK -> ", end='')
                # -> TRUNK
                if vlan_id_destination == 'T':
                    print("DESTINATION TRUNK\n")
                    forward_frame(data, length, MAC_Table[dest_mac])
                # -> ACCES
                else:
                    print("DESTINATION ACCES -> ", end='')
                    # HAVE THE SAME VLAN ID
                    vlan_src = int.from_bytes(data[14:16], byteorder='big')
                    if int(vlan_id_destination) == vlan_src:
                        # REMOVE HEADER
                        no_header_data = data[0:12] + data[16:]
                        print("[SUCCES] Same Vlan ID...\n")
                        forward_frame(no_header_data, length - 4, MAC_Table[dest_mac])
                    else:
                        print("[FAIL] Mismatch Vlan ID...\n")

        else:
            for output_interface in interfaces:
                if output_interface != interface:
                    
                    print("[ROUTE MULTICAST -> SEND ON INTERFACE {} ({})]".format(output_interface, get_interface_name(output_interface)))

                    vlan_id_received = ports[get_interface_name(interface)]
                    print("[VLAN ID SOURCE] Vlan ID : {}".format(vlan_id_received))
                    vlan_id_destination = ports[get_interface_name(output_interface)]
                    print("[VLAN ID DESTINATION] Vlan ID : {}".format(vlan_id_destination))
                    
                    # ACCES
                    if vlan_id_received != 'T' :
                        print("SOURCE ACCES -> ", end='')
                        # -> TRUNK
                        if vlan_id_destination == 'T':
                            # ADD HEADER
                            print("DESTINATION TRUNK\n")
                            header_data = data[0:12] + create_vlan_tag(int(vlan_id_received)) + data[12:]
                            forward_frame(header_data, length + 4, output_interface) 
                        # -> ACCES
                        else:
                            print("DESTINATION ACCES -> ", end='')
                            # HAVE THE SAME VLAN ID
                            if vlan_id_destination == vlan_id_received:
                                print("[SUCCES] Same Vlan ID...\n")
                                forward_frame(data, length, output_interface)
                            else:
                                print("[FAIL] Mismatch Vlan ID...\n")

                    # TRUNK
                    if vlan_id_received == 'T':
                        print("SOURCE TRUNK -> ", end='')
                        # -> TRUNK
                        if vlan_id_destination == 'T':
                            print("DESTINATION TRUNK")
                            forward_frame(data, length, output_interface)
                        # -> ACCES
                        else:
                            print("DESTINATION ACCES -> ", end='')
                            # HAVE THE SAME VLAN ID
                            vlan_src = int.from_bytes(data[14:16], byteorder='big')
                            if int(vlan_id_destination) == vlan_src:
                                # REMOVE HEADER
                                print("[SUCCES] Same Vlan ID...\n")
                                no_header_data = data[0:12] + data[16:]
                                forward_frame(no_header_data, length - 4, output_interface)
                            else:
                                print("[FAIL] Mismatch Vlan ID...\n")

        # print_mac_table()

        # TODO: Implement VLAN support

        # ports -> dictionar {interfata, vlan_id}
        # interface -> interfata dupa care a venit frame-ul
        # vlan_id_received -> vlan id-ul de pe interfata respectiva




        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, data, length)

        print("*************** END PACKET *******************\n")

if __name__ == "__main__":
    main()