#NOTE: I've took some code relating to socket programming from here https://stackoverflow.com/questions/17453212/multi-threaded-tcp-server-in-python

import socket
import struct
import thread
import ctypes

clients = [] # a list contains all of the sockets

(TCP_CONN_HTTP, TCP_CONN_FTP, TCP_CONN_SMTP, TCP_CONN_OTHER) = (0, 1, 2, 3) # enum-like valuse for tcp connection type

# Object representing the conn_entry_metadata_t structure of the kernel module
class Metadata(ctypes.Structure):
    _fields_ = [('conn_type', ctypes.c_int),
            ('client_ip', ctypes.c_uint32),
            ('client_port', ctypes.c_uint16),
            ('server_ip', ctypes.c_uint32),
            ('server_port', ctypes.c_uint16),
            ('forged_client_port', ctypes.c_uint16),
            ('random_ftp_data_port', ctypes.c_uint16)]

MetadataSize = ctypes.sizeof(Metadata)

# for PORT commands we should add a connection table entry in the module from the server with port 20 to the client with the port represented in the command
def handle_port_command_if_needed(message, metadata):
    port_command_index = message.find("PORT") # if the is PORT command
    if port_command_index == -1:
        return
    body = message[port_command_index + 5:-2].split(",")
    if len(body) != 6:
        return
    client_ip = body[0] + "." + body[1] + "." + body[2] + "." + body[3] # the first four numbers in the content of the command are the ip address of the client
    if socket.inet_ntoa(struct.pack('I', metadata.client_ip)) != client_ip:
        return
    port = int(body[4]) * 256 + int(body[5]) # this is how we calculate the chosen port for the data connection
    with open("/sys/class/fw/conns/proxy", "wb") as f:
        metadata.random_ftp_data_port = socket.htons(port)
        f.write(metadata)
   
# function which is being called on every message received: here we send it to the other side,
# with a small exception: if our receiving socket is that of the client, we check also if the command is PORT and handle it appropriately.
def onmessage(client, message, i, server, isclient, metadata):
    if isclient:
        print("Client #{} Sent Message: {}".format(i, message.decode()))
    else:
        print("Server #{} Sent Message: {}".format(i, message.decode()))

    if isclient:
        handle_port_command_if_needed(message.decode(), metadata)

    server.send(message)

 # prints the new connection, for debugging purpose   
def onopen(client):
    print("Client Connected: {} --> {}".format(client.getpeername(), client.getsockname()))

# notifies a connection has been closed, for debugging purpose
def onclose(client):
    print("Client Disconnected")
    
# notify the firewall module about the source port of the proxy in the current connection, so he knows how to update the connection table
def create_forged_connection_with_real_server(client, i):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 0)) # here we create a socket for the connection with the real server, meaning we are impersonating to the client
    metadata = 0
    with open("/sys/class/fw/conns/proxy", "r+b") as f:
        metadata_array = f.read() # we are reading all the metadata entries of the current dynamic table in the module
        for i in range(0, len(metadata_array), MetadataSize):
            metadata = Metadata.from_buffer(bytearray(metadata_array[i:i+MetadataSize]))
            # if we find a metadata entry which matches the current connection with the real client, we break because this is the metadata entry we should update
            if metadata.conn_type == TCP_CONN_FTP and client.getpeername() == (socket.inet_ntoa(struct.pack('I', metadata.client_ip)), socket.ntohs(metadata.client_port)):
                break
        
        metadata.forged_client_port = socket.htons(server.getsockname()[1]) # we update the forged client source port for the connection with the real server        
        f.write(metadata)
    print("Trying to connect the server")
    server.connect((socket.inet_ntoa(struct.pack('I', metadata.server_ip)), socket.ntohs(metadata.server_port)))
    print("Server socket for Client #{}{}: {} --> {}".format(i, client.getpeername(), server.getsockname(), server.getpeername()))
    return server, metadata

# here we receive messages and then send them to the othersize
def recieve(client, server, i, isclient, metadata):
    while True:
        data = client.recv(4096)
        if data == b'':
            break
        #Message Received
        onmessage(client, data, i, server, isclient, metadata)
    # now the connection is closed
    if isclient: # here we are in the client side: we remove the client and server socket from the list and close them
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
    else: # here we are on the server side (client is server and server is client), so we just close our socket and shutdown the remote socket (without removing from list)
        onclose(server)
        client.close()
        try:
            server.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
    #Closing thread
    thread.exit()
    
# loop for accepting clients: we accpet a client, create a connection with the server and update the connection table of the module appropriately    
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
        # for each "real" connection we create two threads: of both directions.
        # the first socket is the socket which receives data, and we send it to the second socket.
        # so we are listening to both sockets in parallel and when we get a message we deliver it to the other socket 
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
    proxy.bind(('0.0.0.0', 210)) # we bind the socket to port 210 because we redirect packets with destination port 21 to port 210
    proxy.listen(5)
    run(proxy)

if __name__ == "__main__":
    main()