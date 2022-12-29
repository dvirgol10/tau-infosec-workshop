import socket
import thread
import ctypes

class SocketServer(socket.socket):
    clients = []

    def __init__(self, s_family, s_type):
        socket.socket.__init__(self)
        #To silence- address occupied!!
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.bind(('0.0.0.0', 80))
        self.listen(5)

    def run(self):
        print("Server started")
        try:
            self.accept_clients()
        except Exception as ex:
            print(ex)
        finally:
            print("Server closed")
            for client in self.clients:
                client.close()
            self.close()

    def accept_clients(self):
        i = 0
        while 1:
            (clientsocket, address) = self.accept()
            #Adding client to clients list
            self.clients.append(clientsocket)
            #Client Connected
            self.onopen(clientsocket)
            #Receiving data from client
            thread.start_new_thread(self.recieve, (clientsocket, i))
            i += 1

    def recieve(self, client, i):
        while 1:
            data = client.recv(4096)
            if data == b'':
                break
            #Message Received
            self.onmessage(client, data, i)
        #Removing client from clients list
        self.clients.remove(client)
        #Client Disconnected
        self.onclose(client)
        #Closing connection with client
        client.close()
        #Closing thread
        thread.exit()
        print(self.clients)

    def broadcast(self, message):
        #Sending message to all clients
        for client in self.clients:
            client.send(message)

    def onopen(self, client):
        pass

    def onmessage(self, client, message):
        pass

    def onclose(self, client):
        pass
        
        
        
class BasicChatServer(SocketServer):

    def __init__(self, s_family, s_type):
        SocketServer.__init__(self, s_family, s_type)

    def onmessage(self, client, message, i):
        print("Client #{}{} Sent Message: {}".format(i, client.getpeername(), message.decode()))
        #Sending message to all clients
        #self.broadcast(message)
        client.send("Got it #{}".format(i).encode())
        
    def onopen(self, client):
        print("Client Connected")

    def onclose(self, client):
        print("Client Disconnected")

def main():
    server = BasicChatServer(socket.AF_INET, socket.SOCK_STREAM)
    server.run()

if __name__ == "__main__":
    main()