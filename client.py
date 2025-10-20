import socket
import threading
import datetime as dt

Ip = str
Port = int
Name = str
Fingerprint = str
Address = tuple[Ip, Port]
Client = tuple[Name, Fingerprint, Ip, Port]
Content = str
Message = tuple[Client | Address, Content, dt.datetime]


class P2PClient:
    # SERVER = ("localhost", 33333)

    def __init__(self, server: Address = ("localhost", 33333)):
        self.SERVER = server
        self.name = None
        self.fingerprint = None
        self.quit = threading.Event()
        self.quit.set()
        self.registered = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(3)
        self.clients = []
        self.clientsUpdated = threading.Event()
        self.messageWaiting = threading.Event()
        self.recievedMessages: list[Message] = []
        self.recievedMessagesLock = threading.Lock()
        self.queuedMessages: dict[str, tuple[str, Address]] = {}
        self.queuedMessagesLock = threading.Lock()
        self.recvThread = threading.Thread(target=self.recvLoop)

    def register(self):
        if not self.registered.is_set():
            register = f"ADD_CLIENT\n{self.fingerprint}\n{self.name}"
            self.send(register, self.SERVER)

    def start(self, name, fingerprint):
        if self.quit.is_set():
            self.name = name
            self.fingerprint = fingerprint
            self.quit.clear()
            self.recvThread.start()
            self.register()
        elif not self.registered.is_set():
            self.register()

    def send(self, what: str, to: Address | None = None):
        if not to:
            to = self.SERVER
        self.sock.sendto(bytes(what, "utf-8"), to)

    def sendMessage(self, what: str, to: Address):
        self.queuedMessagesLock.acquire()
        self.queuedMessages[str(hash(what))] = (what, to)
        self.queuedMessagesLock.release()
        self.send(f"MESSAGE\n{hash(what)}\n" + what, to)

    def resendAll(self):
        self.queuedMessagesLock.acquire()
        for key in self.queuedMessages.keys():
            self.sendMessage(*self.queuedMessages[key])
        self.queuedMessagesLock.release()

    def parseClients(self, lines: list[str]):
        self.clients = []
        for i in range(0, len(lines), 4):
            client = [lines[i + x][1:-1] for x in range(3)] + [int(lines[i + 3])]
            self.clients.append(client)
        self.clients.sort(key=(lambda a: a[0]))
        self.clientsUpdated.set()

    def getClientByAddress(self, address: Address):
        for client in self.clients:
            if (client[2], client[3]) == address:
                return client
        return None

    def processMessage(self, message: str, fromAddress: Address):
        ack, message = message.split("\n", 1)
        now = dt.datetime.now()
        self.recievedMessagesLock.acquire()
        if client := self.getClientByAddress(fromAddress):
            self.recievedMessages.append((client, message, now))
        else:
            self.getClients()
            if client := self.getClientByAddress(fromAddress):
                self.recievedMessages.append((client, message, now))
            else:
                self.recievedMessages.append((fromAddress, message, now))
        self.send("ACK\n" + ack, fromAddress)
        self.messageWaiting.set()
        self.recievedMessagesLock.release()

    def consumeMessages(self) -> list[Message]:
        if self.messageWaiting.is_set():
            self.recievedMessagesLock.acquire()
            out = self.recievedMessages
            self.recievedMessages = []
            self.messageWaiting.clear()
            self.recievedMessagesLock.release()
            return out
        return []

    def clearMessage(self, key):
        self.queuedMessagesLock.acquire()
        del self.queuedMessages[key]
        self.queuedMessagesLock.release()

    def recvLoop(self):
        while not self.quit.is_set():
            try:
                result, fromAddress = self.sock.recvfrom(1 << 12)
                result = str(result, "utf-8").strip().split("\n")
                match result[0]:
                    case "REGISTER_SUCCESS":
                        self.registered.set()
                    case "CLIENTS":
                        threading.Thread(
                            target=self.parseClients, args=[result[1:]]
                        ).start()
                    case "MESSAGE":
                        threading.Thread(
                            target=self.processMessage,
                            args=["\n".join(result[1:]), fromAddress],
                        ).start()
                    case "ACK":
                        threading.Thread(
                            target=self.clearMessage, args=[result[1]]
                        ).start()
            except socket.timeout:
                pass

    def getClients(self) -> list[Client]:
        self.clientsUpdated.clear()
        self.send("GET_CLIENTS")
        self.clientsUpdated.wait()
        return self.clients

    def disconnect(self):
        if not self.quit.is_set():
            self.send("DISCONNECT")
            self.quit.set()
            self.registered.clear()
