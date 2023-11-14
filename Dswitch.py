#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name


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
VLAN_Table = {} # Initialize an empty VLAN table

def forward_frame(data, port_to_send, length, port_received, vlan_id):

    # Implementation of the forward_frame function
    vlan_received = VLAN_Table.get(get_interface_name(port_received))
    vlan_to_send = VLAN_Table.get(get_interface_name(port_to_send))

    if vlan_received != 'T': # from interface access
        if vlan_to_send == 'T': # to interface trunk
            # add vlan tag
            data = data[0:12] + create_vlan_tag(int(vlan_received)) + data[12:]
            length += 4
            print(f'access to trunk')
        else: # to interface access
            if int(vlan_received) != int(vlan_to_send): # to interface access with different vlan
                print(f'access to access with different vlan')
                return
            else:
                print(f'access to access: from {port_received} to {port_to_send}')
                print(f'fwd data length: {len(data)}')
                send_to_link(port_to_send, data, length)
                return
    else: # from interface trunk
        # to interface trunk => no modification
        if vlan_to_send != 'T': # to interface access
            if int(vlan_id) == int(vlan_to_send): # same vlan
                print(f'trunk to access')
                data = data[0:12] + data[16:]
                length -= 4
            else: # different vlan
                print(f'trunk to access with different vlan')
                return
        else: # to interface trunk
            print(f'trunk to trunk')
    
    send_to_link(port_to_send, data, length)

def is_unicast(address):
    # Implementation of the is_unicast function
    # Extract the most significant byte
    msb = int(address.split(':')[0], 16)
    # Check if the least significant bit of the most significant byte is 0
    return (msb & 1) == 0

def print_mac_table():
    # Implementation of the print_mac_table function
    print("MAC Table:")
    for key, value in MAC_Table.items():
        print(key, ":", value)
    print("\n")
    
def parse_switch_cfg(switch_id):
    # Implementation of the parse_switch_cfg function
    file_path = "configs/switch" + switch_id + ".cfg";
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    line = line.split(" ")
                    if len(line) == 2:
                        VLAN_Table[line[0]] = line[1]
    except FileNotFoundError:
        print("File not found")
    except Exception as e:
        print(e)

########################################################################

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    print(f'switch_id: {switch_id}')
    parse_switch_cfg(switch_id)

    for i in VLAN_Table:
        print(i, ":", VLAN_Table[i])

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        print(f'VLAN ID: {vlan_id}') 
        vlan = VLAN_Table.get(get_interface_name(interface))
        print(f'VLAN PORT RECEIVED: {vlan}')

        print(f'main data length: {len(data)}')

        MAC_Table[src_mac] = interface
        
        if(is_unicast(dest_mac)):
            # print(f'unicast')
            if dest_mac in MAC_Table:
                # print(f'forward to port {MAC_Table[dest_mac]}')
                forward_frame(data, MAC_Table[dest_mac], length, interface, vlan_id)
            else:
                # Flood the frame on all ports except the incoming one
                for port in interfaces:
                    if port != interface:
                        # print(f'flood to port {port}')
                        forward_frame(data, port, length, interface, vlan_id)
        else:
            # Flood the frame on all ports except the incoming one
            # print(f'multicast')
            for port in interfaces:
                if port != interface:
                    # print(f'flood to port {port}')
                    forward_frame(data, port, length, interface, vlan_id)


        print("\n")

        # print_mac_table()

        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
