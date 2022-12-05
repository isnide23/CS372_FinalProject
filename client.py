# Author: Ian Snyder
# CS372 Final Project
import sys
import socket
import json
import time
import threading

from chatui import init_windows, read_command, print_message, end_windows

nick = sys.argv[1]
server_addr = sys.argv[2]
port = int(sys.argv[3])

buffer = b''

hello_dict = {
    "type": "hello",
    "nick": nick
}

chat_dict = {
    "type": "chat",
    "message": ""
}

def decode_packet(packet):
    return json.loads(packet[2:].decode())

def get_next_packet(s):
    global buffer

    packet_buffer = buffer

    while True:
    # if i have complete packet then slice
        if len(packet_buffer) >= 2:
            word_length = int.from_bytes(packet_buffer[:2], "big")
            packet_size = word_length + 2
            if packet_size <= len(packet_buffer):
                packet = packet_buffer[:packet_size]
                packet_buffer = packet_buffer[packet_size:]
                return packet 
        chunk = s.recv(5)
        if len(chunk) == 0:
            return None
        packet_buffer += chunk

def build_packet(dict):
    json_data = json.dumps(dict).encode()
    packet_len = len(json_data)
    ready_packet = packet_len.to_bytes(2, "big") + json_data
    return ready_packet

def runner():
    global s

    while True:
        packet = get_next_packet(s)
        decoded_packet = decode_packet(packet)
        # join broadcast
        if decoded_packet['type'] == 'join' and decoded_packet['nick'] != nick:
            print_message(f"*** {decoded_packet['nick']} has joined the chat")
        elif decoded_packet['type'] == 'chat' and decoded_packet['nick'] != nick:
            print_message(f"{decoded_packet['nick']}: {decoded_packet['message']}")
        elif decoded_packet['type'] == 'leave' and decoded_packet['nick'] != nick:
            print_message(f"*** {decoded_packet['nick']} has left the chat")
        else:
            pass
       
init_windows()

# Make the client socket and connect
s = socket.socket()
s.connect((server_addr, port))
s.sendall(build_packet(hello_dict))

# reciever thread
t1 = threading.Thread(target=runner, daemon=True)
t1.start()

# input loop
while True:
    try:
        command = read_command(f"{hello_dict['nick']}> ")
    except:
        break
    if command.startswith('\\q'):
        sys.exit()
    else:
        print_message(f">>> {command}")
        chat_dict["message"] = command
        s.sendall(build_packet(chat_dict))
    

end_windows()





