import socket


#
# CONSTANTS
#
PORT_XTALK = 1993
PROTO_KEY_MESSAGE_STATUS = "status"
PROTO_KEY_PAYLOAD = "body"
PROTO_KEY_RECIPIENT = "to"
##########


class Adapter():
        def __init__(self):
                self.messengerAddress = ("127.0.0.1", PORT_XTALK)
                # SOCKET SETUP
                self.messengerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        
        def checkStatus(self, messageIdentifier):
                self.messengerSock.connect(self.messengerAddress)

                messageStatus = f"{PROTO_KEY_MESSAGE_STATUS}: {messageIdentifier}"

                delimiter = "\r\n"
                self.messengerSock.sendall(messageStatus.encode())
                self.messengerSock.sendall(delimiter.encode())
                # Terminate message.
                self.messengerSock.sendall(delimiter.encode())

                status = ""
                while 1:
                        data = self.messengerSock.recv(1)
                        status += data.decode()
                        if delimiter in status:
                                status = status.strip()
                                break

                self.messengerSock.shutdown(socket.SHUT_RDWR)
                self.messengerSock.close()
                return status

        def send(self, recipient, payload):
                if payload is None or len(payload) == 0:
                        raise ValueError("xTalk: payload is empty!")

                self.messengerSock.connect(self.messengerAddress)
                
                delimiter = "\r\n"

                if recipient is not None:
                        recipientLine = f"{PROTO_KEY_RECIPIENT}: {recipient}"
                        self.messengerSock.sendall(recipientLine.encode())
                        self.messengerSock.sendall(delimiter.encode())
                
                bodyLine = f"{PROTO_KEY_PAYLOAD}: {payload}"
                self.messengerSock.sendall(bodyLine.encode())
                self.messengerSock.sendall(delimiter.encode())
                # Terminate message.
                self.messengerSock.sendall(delimiter.encode())

                receipt = ""
                while 1:
                        data = self.messengerSock.recv(1)
                        receipt += data.decode()
                        if delimiter in receipt:
                                receipt = receipt.strip()
                                break
                 
                self.messengerSock.shutdown(socket.SHUT_RDWR)
                self.messengerSock.close()
                return receipt
