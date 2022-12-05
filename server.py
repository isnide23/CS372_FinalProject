# Author: Ian Snyder
# CS372 Final
import select
import socket
import sys
import json

packet_dict = {}
client_dict = {}

def decode_packet(packet):
    return json.loads(packet[2:].decode())

def build_packet(dict):
    json_data = json.dumps(dict).encode()
    packet_len = len(json_data)
    ready_packet = packet_len.to_bytes(2, "big") + json_data
    return ready_packet

def get_next_packet(s):
    packet_buffer = packet_dict[s]

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

def run_server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))
    s.listen()

    read_set = [s]
    # main loop:
    while True:
    # call select() and get the sockets that are ready to read
        ready_to_read, _, _ = select.select(read_set, {}, {})

    # for all sockets that are ready to read:
        for ready_socket in ready_to_read:
        #   if the socket is the listener socket:
        #   accept() a new connection
        #   add the new socket to our set!
            if ready_socket is s:
                client_con, client_addr = s.accept()
                print(f"{client_addr}: connected")

                read_set.append(client_con)
                packet_dict[client_con] = b''
        #   else the socket is a regular socket:
        #   recv() the data from the socket
            else:
                packet = get_next_packet(ready_socket)
        #   if you receive zero bytes
        #   the client hung up
        #   remove the socket from the set
                if not packet:
                    print(f"{client_dict[ready_socket]}: disconnected")
                    leave_payload = {"type": "leave",
                        "nick": client_dict[ready_socket]
                        }
                    for clients in read_set:
                        if clients != s: 
                            clients.sendall(build_packet(leave_payload))
                            print(f"LEAVE PAYLOAD: {build_packet(leave_payload)}")
                    read_set.remove(ready_socket)
                else:
                    decoded_packet = decode_packet(packet)
                    # CASES:
                    # hello & join
                    # if hello packet add nick to connected client dictionary
                    # broadcast a join message to all clients except the sender
                    if decoded_packet['type'] == 'hello':
                        client_dict[ready_socket] = decoded_packet['nick']
                        for k in client_dict:
                            print(client_dict[k])
                        join_payload = {"type": "join",
                        "nick": client_dict[ready_socket]
                        }
                        for clients in read_set:
                            if clients != s: 
                                clients.sendall(build_packet(join_payload))
                                print(f"JOIN PAYLOAD: {build_packet(join_payload)}")
                    
                    # chat
                    elif decoded_packet['type'] == 'chat':
                        # server should broadcast chat message to all clients excpet sender
                        print(f"CHAT PAYLOAD: {build_packet(decoded_packet)}")
                        decoded_packet["nick"] = client_dict[ready_socket]
                        for clients in read_set:
                            if clients != s: 
                                clients.sendall(build_packet(decoded_packet))
                                print(f"CHAT PAYLOAD: {build_packet(decoded_packet)}")
                    # disconnect
                    elif decode_packet['type'] == 'leave':
                        # server should broadcast leave message to all clients
                        pass
                    else:
                        pass
                   


def usage():
    print("usage: python chat_server.py 3490", file=sys.stderr)

def main(argv):
    try:
        port = int(argv[1])
    except:
        usage()
        return 1

    run_server(port)

if __name__ == "__main__":
    sys.exit(main(sys.argv))