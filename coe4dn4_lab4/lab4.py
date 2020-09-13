#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import threading
import struct
import select

########################################################################

# Read in the config.py file to set various addresses and ports.
from config import *

Cmesg = b'Commands Available: connect.'
CRDSmesg = b'CRDS Commands Available: getdir, makeroom, deleteroom, name, chat, bye.'

########################################################################
#Client class
########################################################################

class Client:
    HOSTNAME = socket.gethostname()

    TIMEOUT = 2
    RECV_SIZE = 256
    PORT = 8000
    TTL = 32  # Hops #try 32
    TTL_SIZE = 1  # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    exiting = False

    # OR: TTL_BYTE = struct.pack('B', TTL)

    thread_flag = 1

    def __init__(self):

        self.prompt_user_forever()

    def create_udp_socket(self):
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def create_get_socket(self,address_port):
        try:
            self.get_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.get_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that deterimines what packets make it to the
            # UDP app.
            self.get_socket.bind((RX_BIND_ADDRESS, address_port[1]))

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces.
            ############################################################

            multicast_group_bytes = socket.inet_aton(address_port[0])

            print("Multicast Group: ", address_port[0])

            # Set up the interface to be used.
            multicast_if_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes

            # You can use struct.pack to create the request, but it is more complicated, e.g.,
            # 'struct.pack("<4sl", multicast_group_bytes,
            # int.from_bytes(multicast_if_bytes, byteorder='little'))'
            # or 'struct.pack("<4sl", multicast_group_bytes, socket.INADDR_ANY)'

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", address_port[0], "/", RX_IFACE_ADDRESS)
            self.get_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def create_tcp_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)


    def connect_to_server(self):
        try:
            self.tcp_socket.connect((Client.HOSTNAME, Client.PORT))
        except Exception as msg:
            print(msg)
            exit()


    def prompt_user_forever(self):

        name = "anonymous"

        while True:
            self.create_tcp_socket()
            connect_prompt_input = input("\n" + "Command: ")

            if connect_prompt_input == "connect":
                self.connect_to_server()
                self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))

                while True:

                    connect_prompt_input = input("\n" + "CRDS Command: ")

                    if connect_prompt_input == "getdir":
                        self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))
                        data = self.tcp_socket.recv(Client.RECV_SIZE)
                        print("Chatrooms Available: ", data.decode("utf-8"))

                    elif connect_prompt_input[:9] == "makeroom ":  # makeroom <chat room name> <address> <port>
                        self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))

                    elif connect_prompt_input[:11] == "deleteroom ":
                        self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))

                    elif connect_prompt_input[:5] == "name ":
                        name = connect_prompt_input.split()[1]

                    elif connect_prompt_input == "bye":
                        self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))
                        self.tcp_socket.close()
                        break

                    elif connect_prompt_input[:5] == "chat ":
                        self.exiting = False
                        self.chatmode(connect_prompt_input, name)
                        break

                    else:
                        print("Invalid Command.")
                        print(CRDSmesg.decode("utf-8"))

            else:
                print("Invalid Command.\n")
                print(Cmesg.decode("utf-8"))
                continue

    def recv_loop(self, connection, username):
        while True:
            if self.exiting:
                print("Ending receive loop")
                return

            (readable, writable, errored) = select.select([connection], [], [connection], 0)

            if readable or errored:
                data, addr_port = connection.recvfrom(Client.RECV_SIZE)
                name = data.decode("utf-8").split(':')[0]
                if name != username:
                    print(data.decode("utf-8"))

    def chatmode(self, connect_prompt_input, username):

        self.tcp_socket.sendall(connect_prompt_input.encode("utf-8"))
        address_port_str = self.tcp_socket.recv(Client.RECV_SIZE).decode("utf-8").split(',') # ("address", "port")
        address_port = (address_port_str[0][2:-1], int(address_port_str[1][2:-2]))  # [1:] to get rid of the space

        self.create_udp_socket()

        self.create_get_socket(address_port)

        threading.Thread(target=self.recv_loop, args=(self.get_socket, username)).start()

        print("-----------------------------CHATTING---------------------------\n")

        while True:
            text = input()
            if text == 'exit':
                self.exiting = True
                break
            msg = username + ": " + text
            self.udp_socket.sendto(msg.encode("utf-8"), address_port)


########################################################################
#Server class
########################################################################

class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 8000
    MAX_CONNECTION_BACKLOG = 10
    RECV_SIZE = 256
    list = []

    def __init__(self):
        self.create_tcp_socket()
        self.receive_forever()

    def create_tcp_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.tcp_socket.bind((Server.HOSTNAME, Server.PORT))

            # Set socket to listen state.
            self.tcp_socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Server listening on port {}...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def send_all(message):
        for connection in connections:
            print("Sending %s" % message)
            connection.send(message)

    def receive_forever(self):
        connections = set()
        while True:
            try:
                (readable, writable, errored) = select.select([self.tcp_socket] + list(connections), [], [])
            except:
                continue
            for connection in readable:
                # If it's the main socket, then it's a new connection, otherwise it's a new message
                if connection == self.tcp_socket:
                    print("New connection received")
                    (connection, address_port) = self.tcp_socket.accept()
                    connections.add(connection)
                else:
                    # A message has been sent to us or the connection is closed
                    message = connection.recv(1024)

                    if not message:
                        print("Connection closed")
                        connections.remove(connection)

                    try:
                        cmd = message.decode("utf-8")
                    except:
                        print("Closing client connection ... ")
                        connections.remove(connection)

                    if cmd == "bye":
                        print("Connection {}".format(address_port) + " disconnected.")
                        connections.remove(connection)

                    else:

                        if cmd == "connect":
                            print("Receiving Connection from {}".format(address_port))

                        elif cmd == "getdir":
                            data = str(Server.list).encode("utf-8")
                            connection.sendall(data)

                        elif cmd[:9] == "makeroom ":  # makeroom <chat room name> <address> <port>
                            room_info = cmd.split()
                            room_name = room_info[1]
                            room_address = room_info[2]
                            room_port = room_info[3]
                            room = (room_name, room_address, room_port)
                            Server.list.append(room)

                        elif cmd[:11] == "deleteroom ":  # deleteroom <chat room name>
                            room_info = cmd.split()
                            room_name = room_info[1]
                            for chatroom in Server.list:
                                if room_name in chatroom:
                                    del Server.list[Server.list.index(chatroom)]
                                else:
                                    print(room_name, " is not in the list.")

                        elif cmd[:5] == "chat ":
                            room_addr_port = b"Room not Found."
                            room_name = cmd.split()[1]
                            for chatroom in Server.list:
                                if room_name in chatroom:
                                    room_addr_port = str((chatroom[1], chatroom[2])).encode("utf-8")
                                    print("{}".format(address_port) + " in chat room " + str(chatroom[0]))
                                    break
                            connection.sendall(room_addr_port)

########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'server': Server, 'client': Client}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='client or server role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################





