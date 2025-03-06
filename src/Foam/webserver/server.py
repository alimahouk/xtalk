#!/usr/bin/env python3

# server.py | v0.1.1 | 23/08/2019 | by alimahouk
# ------------------------------------------------
# ABOUT THIS FILE
# ------------------------------------------------
# This file contains a very rudimentary web server for an
# xTalk-based web browser demo. This server will only work
# with the Foam browser.

import os
import socket
import threading
import pathlib


class WebServer():
        PORT_XTALK = 1993
        PORT_WEB = 5000

        def __init__(self, port=PORT_WEB):
                self.port = port
                # SOCKET SETUP
                self.messengerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.messengerSock.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_KEEPALIVE, 
                        1
                        )
                self.messengerSock.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_REUSEADDR, 
                        1
                        )
                self.messengerSock.setsockopt(
                        socket.IPPROTO_TCP, 
                        socket.TCP_NODELAY, 
                        1
                        )

                serverAddress = ("0.0.0.0", port)
                self.webSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.webSock.setsockopt(
                        socket.SOL_SOCKET, 
                        socket.SO_REUSEADDR, 
                        1
                        )
                self.webSock.setsockopt(
                        socket.IPPROTO_TCP, 
                        socket.TCP_NODELAY, 
                        1
                        )
                self.webSock.bind(serverAddress)
        
        def addressResponse(self, clientIdentifier, messageIdentifier):
                address = self.localAddress()
                recipient = f"to: http@{clientIdentifier}"
                inReplyTo = f"re: {messageIdentifier}"
                body = f"body: {address}:{self.port}"

                delimiter = "\r\n"
                self.messengerSock.sendall(recipient.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
                self.messengerSock.sendall(inReplyTo.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
                self.messengerSock.sendall(body.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
        
        def connect(self):
                messengerAddress = ("127.0.0.1", self.PORT_XTALK)
                self.messengerSock.connect(messengerAddress)
                self.registerInterest()

                while 1:
                        try:
                                line = ""
                                while "\r\n\r\n" not in line:
                                        buffer = self.messengerSock.recv(1)
                                        if len(buffer) > 0:
                                                line += buffer.decode("utf-8")
                                        else:
                                                # No more data from this client (due to a disconnection).
                                                break
                                
                                clientIdentifier = None
                                messageIdentifier = None

                                line = line.strip()
                                lines = line.split("\r\n")
                                for line in lines:
                                        if line.startswith("from:"):
                                                lineParts = line.split(":", 1)
                                                # This server's only response to any message is its
                                                # own IP address and port. It responds to the identifier of 
                                                # the client attempting to connect to it.
                                                clientIdentifier = lineParts[1].strip()
                                        elif line.startswith("ref:"):
                                                lineParts = line.split(":", 1)
                                                messageIdentifier = lineParts[1].strip()
                                self.addressResponse(clientIdentifier, messageIdentifier)
                        except Exception as e:
                                print("Messenger.connect():", e)
                                break
        
        def getDocument(self, path):
                fullPath = pathlib.Path().absolute() / path
                if os.path.exists(fullPath):
                        f = open(fullPath, "r")
                        return f.read()
                else:
                        return None

        def handleClientConnection(self, connection):
                try:
                        line = ""
                        while "\r\n\r\n" not in line:
                                buffer = connection.recv(1)
                                if len(buffer) > 0:
                                        line += buffer.decode("utf-8")
                                else:
                                        # No more data from this client (due to a disconnection).
                                        break
                        
                        line = line.strip()
                        if line.startswith("GET"):
                                lineParts = line.split(" ", 1)
                                path = lineParts[1]
                                if path == "/":
                                        path = "index.html"
                                elif path.startswith("/"):
                                        # Get rid of leading slash.
                                        path = path[1:]

                                print("CLIENT WANTS:", pathlib.Path(path))
                                doc = self.getDocument(pathlib.Path(path))
                                if doc is None:
                                        doc = self.getDocument("404.html")
                                
                                delimiter = "\r\n"
                                connection.sendall(doc.encode("utf-8"))
                                connection.sendall(delimiter.encode("utf-8"))
                                connection.sendall(delimiter.encode("utf-8"))
                except Exception as e:
                        print("WebServer.handleAppConnection():", e)
                finally:
                        connection.close()

        def listenForRequests(self):
                self.webSock.listen(1)
                while 1:
                        print("WAITING FOR WEB REQUEST…")
                        connection, clientAddress = self.webSock.accept()

                        print(f"--[CONNECTION FROM {clientAddress}]--")

                        clientThread = threading.Thread(target=self.handleClientConnection, args=(connection,))
                        clientThread.daemon = True
                        clientThread.start()

        def localAddress(self):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                        # Doesn't even have to be reachable.
                        sock.connect(("10.255.255.255", 1))
                        address = sock.getsockname()[0]
                except Exception:
                        address = "127.0.0.1"
                finally:
                        sock.close()
                return address
        
        def registerInterest(self):
                message = "interest: http"
                delimiter = "\r\n"
                self.messengerSock.sendall(message.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
                self.messengerSock.sendall(delimiter.encode("utf-8"))
        
        def start(self):
                # Spawn a different thread to talk to xTalk.
                messengerThread = threading.Thread(target=self.connect)
                messengerThread.daemon = True
                messengerThread.start()
                # This final method call is blocking.
                self.listenForRequests()


if __name__ == "__main__":
        server = WebServer()
        server.start()
