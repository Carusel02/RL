#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

# ------------------------- GLOBAL VARIABLES -------------------------
own_bridge_ID = -1
root_bridge_ID = -1
root_path_cost = -1
sender_bridge_ID = -1
# --------------------------------------------------------------------


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

def parse_bdpu_packet(data):
    # Unpack the header fields from the byte array
    # dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    
    dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config = struct.unpack('!6s6sH3sI31s', data[:52])
    return dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config

def parse_bdpu_config(bdpu_config):

    flag, root_ID, root_path_cost, bridge_ID, port_ID, message_age, max_age, hello_time, forward_delay = struct.unpack('!B8sI8sHHHHH', bdpu_config[:38])
    return root_ID, root_path_cost, bridge_ID, port_ID 

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    
    # TODO needs a check if doesnt work
    global own_bridge_ID
    global root_bridge_ID
    
    # send a packet at every second
    while True:
        # if we are not the root bridge, dont send BDPU
        if root_bridge_ID != own_bridge_ID:
            break

        # for every port on a switch (0, 1, 2, 3)
        for i in range(0, len(port_vlan)):
            # for every trunk interface on a switch
            if port_vlan[i] == 'T':
                # send BDPU on trunk interface
                send_to_link(i, create_bpdu(i, 0, 0, 0), len(create_bpdu(i, 0, 0, 0)))
        time.sleep(1)

########################################################################

MAC_Table = {}  # Initialize an empty MAC table
interface_vlan = {} # ports of the switch | entries : {interface_name_trunkport - vlan_id}
ports_trunk = {} # ports of the switch (type trunk) | entries : {interface_name_trunk - mode}
ports = {}

port_vlan = [] # port vlan          | entries {number_port, NUMBER/TRUNK}
port_state = [] # port state        | entries {number_port, BLOCKING/LISTENING}
port_type = [] # port type          | entries {number_port, DESIGNATED/ROOT}

# ************************** STP ****************************************



# ************************************************************************



# ************************** CREATE BDPU **********************************

def create_bpdu(port, flag, new_bridge_ID, new_root_path_cost):
    
    # | DEST | MAC
    dst_mac = b'\x01\x80\xc2\x00\x00\x00' # multicast MAC BDPU
    src_mac = get_switch_mac() # switch MAC
    macs = struct.pack('!6s6s', dst_mac, src_mac)

    # | LLC_LENGTH | LLC_HEADER
    llc_length = struct.pack('!H', 0x0026) # 38 bytes
    llc_header = struct.pack('!BBB', 0x42, 0x42, 0x03) # 3 bytes (42 42 03)

    # BPDU_HEADER | BPDU_CONFIG
    bpdu_header = struct.pack('!HBB', 0x0000, 0x00, 0x00) # 4 bytes (00 00 00 00)

    # USE GLOBAL VARIABLES FOR BPDU CONFIG
    global own_bridge_ID
    global root_bridge_ID
    global sender_bridge_ID
    global root_path_cost

    #print("YYYYYYYYYYYYY [ROOT BRIDGE ID] Root Bridge ID : {}".format(root_bridge_ID))
    #print("YYYYYYYYYYYYY [ROOT PATH COST] Root Path Cost : {}".format(root_path_cost))
    #print("YYYYYYYYYYYYY [SENDER BRIDGE ID] Sender Bridge ID : {}".format(sender_bridge_ID))
    root_ID = own_bridge_ID.to_bytes(8, byteorder='big')
    sender_ID = own_bridge_ID.to_bytes(8, byteorder='big')
    sender_path_cost = root_path_cost


    if flag == 1:
        sender_ID = new_bridge_ID.to_bytes(8, byteorder='big')
        sender_path_cost = new_root_path_cost

    bpdu_config = struct.pack('!B8sI8sHHHHH', 0x00,                 # flag
                                              root_ID,              # root_ID
                                              sender_path_cost,     # path_cost
                                              sender_ID,            # bridge_ID
                                              port,                 # port_ID
                                              0x0000,               # message_age
                                              0x0000,               # max_age
                                              0x0000,               # hello_time
                                              0x0000)               # forward delay

    packet = macs + llc_length + llc_header + bpdu_header + bpdu_config
    return packet


# *************************************************************************

def parse_config_file(switch_id):
    
    # read file location
    file_path = f'configs/switch{switch_id}.cfg'
    print(f"[CONFIG FILE] READ : {file_path}")

    # open file location
    with open(file_path) as file:
       file_content = file.read()
    
    # Split the content into lines
    lines = file_content.split('\n')

    # Extract information from the first line
    PRIO = lines[0]
    print(f"[PRIO] SWITCH : {PRIO}")
    global own_bridge_ID
    own_bridge_ID = int(PRIO)

    switches_info = [line.split() for line in lines[1:] if line]
    
    for switch_info in switches_info:
        print(f"[PORT] SWITCH : {switch_info}")
        # first is interface name
        interface_name = switch_info[0]
        # second is vlan
        vlan = switch_info[1]
        # add vlan to port_vlan
        port_vlan.append(vlan)
        port_state.append("LISTENING")
        port_type.append("NONE")

        # add this
        ports[interface_name] = vlan
        
        # optional
        interface_vlan[interface_name] = vlan


    print(f"[ALL] PORTS VLAN : {port_vlan}")

def forward_frame(data, length, output_interface):
    send_to_link(output_interface, data, length)

def is_unicast(mac):
    dest_mac_bytes = mac.split(':')
    first_byte = int(dest_mac_bytes[0], 16)
    return (first_byte & 1) == 0


########################################################################

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    print("######################## LOAD INFO ########################")
    print(f"[ID] SWITCH ID : {switch_id}")
    
    # make own_bridge_id = switch_prio
    parse_config_file(switch_id)

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print(f"[INFO] START SWITCH ID {switch_id}", flush=True)
    print("[INFO] SWITCH MAC : ", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Printing interface names
    for i in interfaces:
        print(f"[INTERFACE] INTERFACE {i} HAS NAME {get_interface_name(i)}", flush=True)
    print("######################## END INFO ########################\n")

    # set default port state for all interfaces to LISTENING
    for i in interfaces:
        port_state[i] = "LISTENING"
    
    # Initialize STP

    # take global variables
    global own_bridge_ID
    global root_bridge_ID
    global root_path_cost
    
    # for each trunk pork on the switch
    for i in interfaces:
        # trunk port
        if port_vlan == 'T':
            # set the port state to BLOCKING
            port_state[i] = "BLOCKING"
    
    # verify
    for i in interfaces:
        print(f"------> PORT STATE {i} = {port_state[i]}")

    # root bridge ID = priority value
    # we are the root bridge
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0

    # verify
    print(f"OWN BRIDGE ID : {own_bridge_ID}")
    print(f"ROOT BRIDGE ID : {root_bridge_ID}")
    print(f"ROOT PATH COST : {root_path_cost}")

    # daca portul devine root bridge setam porturile ca designated
    # daca noi suntem root bridge, setam porturile (trunk) ca designated
    if root_bridge_ID == own_bridge_ID:
        for i in interfaces:
            if port_vlan[i] == 'T':
                port_type[i] = "DESIGNATED"
    # verify
    for i in interfaces:
        print(f"------> PORT TYPE {i} = {port_type[i]}")

    # Type of packet
    # 1. ICMP (0)
    # 2. BDPU (1)
    packet_type = 0 # default

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].

        for i in interfaces:
            print(f"!!!!! IMPORTANT NOTE PORT STATE : {port_state[i]}")

        interface, data, length = recv_from_any_link()
        print("\n\n*************** PACKET RECEIVED ***************\n")

        dest_mac = data[0:6]
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)

        if dest_mac == "01:80:c2:00:00:00":
            print("@@@@@@@@@@@ [BDPU] @@@@@@@@@@@")
            packet_type = 1
        else:
            print("@@@@@@@@@@@ [ICMP] @@@@@@@@@@@")
            packet_type = 0


        # on receiving a BDPU
        if packet_type == 1:
            print(f"[INFO] Received frame of size {length} on interface {interface} ({get_interface_name(interface)})\n", flush=True)
            
            # extract from data
            dest_mac, src_mac, llc_length, llc_header, bpdu_header, bpdu_config = parse_bdpu_packet(data)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            # extract from bpdu_config
            bpdu_root_ID, bdpu_root_path_cost, bdpu_bridge_ID, bdpu_port_ID = parse_bdpu_config(bpdu_config)
            bdpu_root_ID = int.from_bytes(bpdu_root_ID, byteorder='big')
            bdpu_sender_ID = int.from_bytes(bdpu_bridge_ID, byteorder='big')
            
            print(f"bdpu SI {bdpu_sender_ID} and OBI {own_bridge_ID}")
            

            # info on receive
            print(f"[EXTRACT FROM BDPU] Root Bridge ID : {bdpu_root_ID}")
            print(f"[EXTRACT FROM BDPU] Sender Bridge ID : {bdpu_sender_ID}")
            print(f"[EXTRACT FROM BDPU] Root Path Cost : {bdpu_root_path_cost}")
            print(f"[EXTRACT FROM BDPU] Port ID : {bdpu_port_ID}")


            ################## START PSEUDOCODE ################### 
            
            # if we find a better root bridge
            if bdpu_root_ID < root_bridge_ID:
                
                # if we are the root bridge
                if root_bridge_ID == own_bridge_ID:
                    # set all interfaces to BLOCKING
                    for i in interfaces:
                        # not to hosts (trunk ports) except root port
                        if port_vlan[i] == 'T' and i != interface:
                            port_state[i] = "BLOCKING"
                
                # update root bridge ID
                root_bridge_ID = bdpu_root_ID
                # add 10 to the root path cost
                root_path_cost = bdpu_root_path_cost + 10 
                # update root port
                port_type[interface] = "ROOT"

                # if root port state is BLOCKING
                if port_state[interface] == "BLOCKING":
                    # set root port state to LISTENING
                    port_state[interface] = "LISTENING"

                # update and forward BDPU with

                # new sender ID = own bridge ID
                # new sender path cost = root path cost
                
                new_sender_ID = own_bridge_ID # bridge_ID
                new_sender_path_cost = root_path_cost # root_path_cost

                # create new BDPU
                # TODO make create BDPU receive parameters
                new_bpdu = create_bpdu(interface, 1, new_sender_ID, new_sender_path_cost)
                
                # to ALL other trunks
                # ??? it s ok to send not on interface?
                for i in interfaces:
                    if port_vlan[i] == 'T' and i != interface:
                        print("SEND NEW PACKET")
                        send_to_link(i, new_bpdu, len(new_bpdu))

            
            # have the same root bridge ID
            elif bpdu_root_ID == root_bridge_ID:
                
                # the sender is the root bridge
                if port_type[interface] == "ROOT" and bdpu_root_path_cost + 10 < root_path_cost:
                    root_path_cost = bdpu_root_path_cost + 10                    

                # the sender is not the root bridge
                elif port_type[interface] != "ROOT":
                    # Verifica daca portul ar trebui trecut pe designated.
                    # Designated inseamna ca drumul catre root este prin
                    # acest switch. Daca am bloca acest drum, celelalte
                    # switch-uri nu ar mai putea comunica cu root bridge.
                    # Nota: in mod normal ar trebui sa stocam ultimul BPDU
                    # de pe fiecare port ca sa calculam designated port.
                    if bdpu_root_path_cost > root_path_cost:
                        # if the port is not the designated port for the segment
                        if port_type[interface] != "DESIGNATED":
                            # set port to DESIGNATED and set state to LISTENING
                            port_type[interface] = "DESIGNATED"
                            port_state[interface] = "LISTENING"

            
            # the sender is US    
            elif bdpu_sender_ID == own_bridge_ID:
                # set port state to BLOCKING
                print("I NEED TO ENTER HEREEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
                port_state[interface] = "BLOCKING"
            else:
                # discard BDPU
                print("++++ not today...not tommorow...not ever ++++")
                continue
            
            # if we are the root
            if own_bridge_ID == root_bridge_ID:
                for i in interfaces:
                    if port_vlan[i] == 'T':
                        # set port to DESIGNATED
                        port_type[i] = "DESIGNATED"


        # on receiving a ICMP
        if packet_type == 0:
            print(f"[INFO] Received frame of size {length} on interface {interface} ({get_interface_name})\n", flush=True)
            
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
            

            # we have a UNICAST FRAME and WE KNOW WHERE TO SEND it + ADD LISTENING
            if is_unicast(dest_mac) and dest_mac in MAC_Table and port_state[MAC_Table[dest_mac]] == "LISTENING":
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
                    if output_interface != interface and port_state[output_interface] == "LISTENING":
                        
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


        print("*************** END PACKET *******************\n")

        for i in interfaces:
            print(f"- - - - - > PORTS : {port_state[i]} ", end='')
            print('\n')

if __name__ == "__main__":
    main()