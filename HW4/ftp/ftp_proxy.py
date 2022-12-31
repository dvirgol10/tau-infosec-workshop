#NOTE: I've took some code relating to socket programming from here https://stackoverflow.com/questions/17453212/multi-threaded-tcp-server-in-python

import socket
import struct
import thread
import ctypes

clients = []

(TCP_CONN_HTTP, TCP_CONN_FTP, TCP_CONN_OTHER) = (0, 1, 2)

class Metadata(ctypes.Structure):
    _fields_ = [('conn_type', ctypes.c_int),
            ('client_ip', ctypes.c_uint32),
            ('client_port', ctypes.c_uint16),
            ('server_ip', ctypes.c_uint32),
            ('server_port', ctypes.c_uint16),
            ('forged_client_port', ctypes.c_uint16),
            ('random_ftp_data_port', ctypes.c_uint16)]

MetadataSize = ctypes.sizeof(Metadata)


def handle_port_command_if_needed(message, metadata):
    port_command_index = message.find("PORT")
    if port_command_index == -1:
        return
    body = message[port_command_index + 5:-2].split(",")
    if len(body) != 6:
        return
    client_ip = body[0] + "." + body[1] + "." + body[2] + "." + body[3]
    if socket.inet_ntoa(struct.pack('I', metadata.client_ip)) != client_ip:
        return
    port = int(body[4]) * 256 + int(body[5])
    with open("/sys/class/fw/conns/proxy", "wb") as f:
        metadata.random_ftp_data_port = socket.htons(port)
        f.write(metadata)
   

def onmessage(client, message, i, server, isclient, metadata):
    if isclient:
        print("Client #{} Sent Message: {}".format(i, message.decode()))
    else:
        print("Server #{} Sent Message: {}".format(i, message.decode()))

    if isclient:
        handle_port_command_if_needed(message.decode(), metadata)

    server.send(message)

    
def onopen(client):
    print("Client Connected: {} --> {}".format(client.getpeername(), client.getsockname()))


def onclose(client):
    print("Client Disconnected")
    

def create_forged_connection_with_real_server(client, i):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 0))
    metadata = 0
    with open("/sys/class/fw/conns/proxy", "r+b") as f:
        metadata_array = f.read()
        for i in range(0, len(metadata_array), MetadataSize):
            metadata = Metadata.from_buffer(bytearray(metadata_array[i:i+MetadataSize]))
            if metadata.conn_type == TCP_CONN_HTTP and client.getpeername() == (socket.inet_ntoa(struct.pack('I', metadata.client_ip)), socket.ntohs(metadata.client_port)):
                break
        
        metadata.forged_client_port = socket.htons(server.getsockname()[1])        
        f.write(metadata)
    print("Trying to connect the server")
    server.connect((socket.inet_ntoa(struct.pack('I', metadata.server_ip)), socket.ntohs(metadata.server_port)))
    print("Server socket for Client #{}{}: {} --> {}".format(i, client.getpeername(), server.getsockname(), server.getpeername()))
    return server, metadata


def recieve(client, server, i, isclient, metadata):
    while True:
        data = client.recv(4096)
        if data == b'':
            break
        #Message Received
        onmessage(client, data, i, server, isclient, metadata)
    if isclient:
        #Removing client from clients list
        clients.remove(client)
        clients.remove(server)
        #Client Disconnected
        onclose(client)
        #Closing connection with client
        client.close()
        try:
            server.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
    else:
        onclose(server)
        client.close()
        try:
            server.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
    #Closing thread
    thread.exit()
    
    
def accept_clients(proxy):
    i = 0
    while True:
        clientsocket, _ = proxy.accept()
        #Adding client to clients list
        clients.append(clientsocket)
        #Client Connected
        onopen(clientsocket)
        serversocket, metadata = create_forged_connection_with_real_server(clientsocket, i)
        clients.append(serversocket)
        #Receiving data from client
        thread.start_new_thread(recieve, (clientsocket, serversocket, i, True, metadata))
        thread.start_new_thread(recieve, (serversocket, clientsocket, i, False, metadata))
        i += 1
        

def run(proxy):
    print("Proxy started")
    try:
        accept_clients(proxy)
    except Exception as e:
        print(e)
    finally:
        print("Proxy closed")
        for client in clients:
            client.close()
        proxy.close()

def main():
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(('0.0.0.0', 210))
    proxy.listen(5)
    run(proxy)

if __name__ == "__main__":
    main()