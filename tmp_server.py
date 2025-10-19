import socketserver


class udphandle(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request[1].sendto(self.request[0], self.client_address)


with socketserver.ThreadingUDPServer(("localhost", 33333), udphandle) as server:
    server.serve_forever()
