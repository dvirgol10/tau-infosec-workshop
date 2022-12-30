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
            ('forged_client_port', ctypes.c_uint16)]

MetadataSize = ctypes.sizeof(Metadata)

   
def onmessage(client, message, i, server):
    print("Client #{} Sent Message: {}".format(i, message.decode()))
    #Sending message to all clients
    #self.broadcast(message)
    #client.send("Got it".encode())
    server.send(message)
    response = server.recv(4096)
    print("Server for Client #{} Sent Response: {}".format(i, response.decode()))
    client.send(response)

    
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
    return server


def recieve(client, server, i):
    while True:
        data = client.recv(4096)
        if data == b'':
            break
        #Message Received
        onmessage(client, data, i, server)
    #Removing client from clients list
    clients.remove(client)
    #Client Disconnected
    onclose(client)
    #Closing connection with client
    client.close()
    server.close()
    #Closing thread
    thread.exit()
    
    
def accept_clients(proxy):
    i = 0
    while True:
        (clientsocket, address) = proxy.accept()
        #Adding client to clients list
        clients.append(clientsocket)
        #Client Connected
        onopen(clientsocket)
        serversocket = create_forged_connection_with_real_server(clientsocket, i)

        #Receiving data from client
        thread.start_new_thread(recieve, (clientsocket, serversocket, i))
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
    proxy.bind(('0.0.0.0', 800))
    proxy.listen(5)
    run(proxy)

if __name__ == "__main__":
    main()