//
//  Networking.swift
//  Foam
//
//  Created by alimahouk on 25/08/2019.
//  Copyright © 2019 alimahouk. All rights reserved.
//

import CocoaAsyncSocket
import Cocoa

class Networking: NSObject, GCDAsyncSocketDelegate {
	
	public static let shared = Networking()
	private static var xTalkSocket: GCDAsyncSocket!
	private static var webSocket: GCDAsyncSocket!
	
	deinit {
		NotificationCenter.default.removeObserver(self)
	}
	
	private override init() {
		super.init()
		
		Networking.xTalkSocket = GCDAsyncSocket.init(delegate: self,
							    delegateQueue: .main)
		Networking.xTalkSocket.perform({
			var flagOn: UInt32 = 1
			if setsockopt(Networking.xTalkSocket.socketFD(), SOL_SOCKET, TCP_KEEPALIVE, &flagOn, socklen_t(MemoryLayout.size(ofValue: flagOn))) == -1 { }
			if setsockopt(Networking.xTalkSocket.socketFD(), SOL_SOCKET, TCP_NODELAY, &flagOn, socklen_t(MemoryLayout.size(ofValue: flagOn))) == -1 { }
		})
		
		Networking.webSocket = GCDAsyncSocket.init(delegate: self,
							   delegateQueue: .main)
		Networking.webSocket.perform({
			var flagOn: UInt32 = 1
			if setsockopt(Networking.webSocket.socketFD(), SOL_SOCKET, TCP_NODELAY, &flagOn, socklen_t(MemoryLayout.size(ofValue: flagOn))) == -1 { }
		})
	}
	
	public static func checkin() {
		var interestValue = ""
		let interests = ["http"]
		for (i, interest) in interests.enumerated() {
			interestValue += interest
			if i < interests.count-1 {
				interestValue += ", "
			}
		}
		
		let message = [PROTO_KEY_SERVICES: interestValue]
		Networking.send(message: message)
	}
	
	public static func connect() {
		if Networking.xTalkSocket.isConnected {
			Networking.xTalkSocket.disconnectAfterReadingAndWriting()
		}
		
		do {
			print("Connecting to xTalk…")
			try Networking.xTalkSocket.connect(toHost: NET_SERV_ADDR,
							  onPort: NET_SERV_PORT,
							  withTimeout: TimeInterval(NET_SOCK_TIMEOUT))
		} catch let error {
			print(error)
		}
	}
	
	public static func connectTo(host: String, port: UInt16) {
		if Networking.webSocket.isConnected {
			Networking.webSocket.disconnectAfterReadingAndWriting()
		}
		
		do {
			print("Connecting to \(host):\(port)…")
			try Networking.webSocket.connect(toHost: host,
							 onPort: port,
							 withTimeout: TimeInterval(NET_SOCK_TIMEOUT))
		} catch let error {
			print(error)
			NotificationCenter.default.post(notification: .failedToConnectToServer,
							object: ["host": host, "port": port],
							userInfo: nil)
		}
	}
	
	public static func disconnect() {
		Networking.xTalkSocket.disconnectAfterWriting()
	}
	
	public static func send(message: Dictionary<String, String>) {
		let delimiter = "\r\n"
		for (field, value) in message {
			let message: String
			if value.count > 0 {
				message = field + ": " + value
			} else {
				message = field
			}
			
			Networking.sendData(message.data(using: .utf8)!)
			Networking.sendData(delimiter.data(using: .utf8)!)
		}
		Networking.sendData(delimiter.data(using: .utf8)!)
	}
	
	public static func sendData(_ data: Data) {
		Networking.xTalkSocket.write(data,
                                             withTimeout: -1,
                                             tag: 0)
	}
	
	public static func sendWebData(_ data: Data) {
		Networking.webSocket.write(data,
					   withTimeout: -1,
					   tag: 0)
	}
	
	func socket(_ sock: GCDAsyncSocket,
		    didConnectToHost host: String,
		    port: UInt16) {
		print("Connected to \(host):\(port)")
		
		if sock == Networking.xTalkSocket {
			Networking.checkin()
		} else {
			NotificationCenter.default.post(notification: .connectedToServer,
							object: ["host": host, "port": port],
							userInfo: nil)
		}
		sock.readData(to: "\r\n\r\n".data(using: .utf8)!,
			      withTimeout: -1,
			      tag: 0)
	}
	
	func socket(_ sock: GCDAsyncSocket,
		    didRead data: Data,
		    withTag tag: Int) {
		if var message = String(data: data,
					encoding: .utf8) {
			message = message.trimmingCharacters(in: .whitespacesAndNewlines)
			
			if sock == Networking.xTalkSocket {
				if message.hasPrefix(PROTO_KEY_SERVICES) {
					NotificationCenter.default.post(notification: .checkedIn,
									object: nil,
									userInfo: nil)
				} else if message.hasPrefix(PROTO_KEY_LOCAL_IDENTIFIER) {
					let components = message.components(separatedBy: [":"])
					if components.count == 2 {
						let identifier = components[1].trimmingCharacters(in: .whitespacesAndNewlines)
						NotificationCenter.default.post(notification: .receivedLocalIdentifier,
										object: identifier,
										userInfo: nil)
					}
				} else if message.hasPrefix(PROTO_KEY_SENDER) {
					let lines = message.split { $0 == "\r\n" }
					var sender: String?
					var payload: String?
					
					for line in lines {
						let components = line.split(separator: ":",
									    maxSplits: 1)
						if components[0] == PROTO_KEY_SENDER {
							sender = components[1].trimmingCharacters(in: .whitespacesAndNewlines)
						} else if components[0] == PROTO_KEY_PAYLOAD {
							payload = components[1].trimmingCharacters(in: .whitespacesAndNewlines)
						}
					}
					
					if sender != nil && payload != nil {
						NotificationCenter.default.post(notification: .receivedProtocolMessage,
										object: Message(sender: sender!,
												payload: payload!),
										userInfo: nil)
					}
				}
			} else {
				NotificationCenter.default.post(notification: .receivedWebResponse,
								object: message,
								userInfo: nil)
			}
		}
		
		sock.readData(to: "\r\n\r\n".data(using: .utf8)!,
			      withTimeout: -1,
			      tag: 0)
	}
	
	func socket(_ sock: GCDAsyncSocket,
		    didWriteDataWithTag tag: Int) {
		
	}
	
	func socketDidDisconnect(_ sock: GCDAsyncSocket,
				 withError err: Error?) {
		if let error = err {
			if (error as NSError).code != 7 {
				print(error) /* Server is unreachable. */
				NotificationCenter.default.post(notification: .disconnectedFromServer,
								object: nil,
								userInfo: nil)
			} else {
				if sock == Networking.xTalkSocket {
					print("Disconnected from xTalk!")
					NotificationCenter.default.post(notification: .disconnectedFromServer,
									object: nil,
									userInfo: nil)
				} else {
					print("Disconnected from web server!")
				}
			}
		}
	}
	
}
