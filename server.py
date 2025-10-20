import socketserver
import threading
from copy import deepcopy
import sys

Name, Fingerprint, Ip = str, str, str
Port = int
Client = tuple[Name, Fingerprint, Ip, Port]
Address = tuple[Ip, Port]
if len(sys.argv) == 3:
    SERVER: Address = (sys.argv[1], int(sys.argv[2]))
else:
    SERVER: Address = ("localhost", 33333)


class Clients:
    CLIENT_LOCK = threading.Lock()

    def __init__(self):
        self.clients: list[Client] = []

    def addClient(self, client: Client):
        with self.CLIENT_LOCK:
            self.clients.append(client)
            self.clients.sort(key=(lambda client: client[0]))

    def getClients(self) -> list[Client]:
        outList = []
        with self.CLIENT_LOCK:
            outList = deepcopy(self.clients)
        return outList

    def removeClient(self, toRemove: Address):
        with self.CLIENT_LOCK:
            foundClient = None
            for client in self.clients:
                if client[2:] == toRemove:
                    foundClient = client
                    break
            if foundClient:
                self.clients.remove(foundClient)


class PGPUDPHandler(socketserver.BaseRequestHandler):
    clients = Clients()

    def handle(self):
        print(self.request)
        print(self.client_address)
        data, sock = self.request
        if b"\n" in data:
            messageType, message = data.strip().split(b"\n", 1)

            print(messageType, message)
        else:
            messageType = data
        match messageType:
            case b"ADD_CLIENT":
                fingerprint, name = message.split(b"\n", 1)
                client = (
                    str(name, "utf-8"),
                    str(fingerprint, "utf-8"),
                    *self.client_address,
                )
                if client[1] not in [x[1] for x in self.clients.clients]:
                    self.clients.addClient(client)
                sock.sendto(bytes("REGISTER_SUCCESS", "utf-8"), self.client_address)
            case b"GET_CLIENTS":
                clients = self.clients.getClients()
                response = "CLIENTS\n"
                for client in clients:
                    response += "\n".join([repr(item) for item in client]) + "\n"
                sock.sendto(bytes(response, "utf-8"), self.client_address)
            case b"DISCONNECT":
                self.clients.removeClient(self.client_address)


if __name__ == "__main__":
    with socketserver.ThreadingUDPServer(SERVER, PGPUDPHandler) as server:
        server.serve_forever()
