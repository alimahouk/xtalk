//
//  MainWindowController.swift
//  Foam
//
//  Created by alimahouk on 25/08/2019.
//  Copyright © 2019 alimahouk. All rights reserved.
//

import Cocoa
import WebKit

class MainWindowController: NSWindowController, NSTextFieldDelegate, WKNavigationDelegate {
	
	@IBOutlet weak var URLTextField: NSTextField!
	@IBOutlet weak var webView: WKWebView!
	
	var activeURL: URL?
	var activeURLHost: String?
	var activeURLPort: UInt16?
	var localIdentifier: String?
	
	deinit {
		NotificationCenter.default.removeObserver(self)
	}
	
	required init?(coder: NSCoder) {
		super.init(coder: coder)
		/* Register for interesting notifications. */
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didCheckIn),
					       notification: .checkedIn,
					       object: nil)
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didConnectToServer(notification:)),
					       notification: .connectedToServer,
					       object: nil)
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didFailToConnectToServer(notification:)),
					       notification: .failedToConnectToServer,
					       object: nil)
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didReceiveLocalIdentifier(notification:)),
					       notification: .receivedLocalIdentifier,
					       object: nil)
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didReceiveProtocolMessage(notification:)),
					       notification: .receivedProtocolMessage,
					       object: nil)
		NotificationCenter.default.add(observer: self,
					       selector: #selector(self.didReceiveWebResponse(notification:)),
					       notification: .receivedWebResponse,
					       object: nil)
	}
	
	override func windowDidLoad() {
		super.windowDidLoad()
		
		URLTextField.becomeFirstResponder()
	}
	
	// MARK: NSTextFieldDelegate
	
	func control(_ control: NSControl,
		     textView: NSTextView,
		     doCommandBy commandSelector: Selector) -> Bool {
		if (commandSelector == #selector(NSResponder.insertNewline(_:))) {
			if textView.string.count > 0 {
				var URLString = textView.string.trimmingCharacters(in: .whitespacesAndNewlines)
				if !URLString.hasPrefix("httpf://") && !URLString.hasPrefix("http://") && !URLString.hasPrefix("https://") {
					URLString = "httpf://" + URLString
				}
				
				if var url = URL(string: URLString) {
					/* Add a trailing slash if necessary. */
					if url.path.count == 0 {
						URLString += "/"
					}
					url = URL(string: URLString)!
					textView.string = url.absoluteString
					self.window?.title = "Loading…"
					
					if url.scheme == "httpf" {
						var host = ""
						/* This adds support for emails potentially being used as identifiers. */
						if let user = url.user {
							host += user
							host += "@"
						}
						host += url.host!
						
						if let activeURL = self.activeURL {
							var activeHost = ""
							if let user = activeURL.user {
								activeHost += user
								activeHost += "@"
							}
							activeHost += activeURL.host!
							
							if activeHost == host {
								Networking.connectTo(host: self.activeURLHost!,
										     port: self.activeURLPort!)
							} else {
								self.findHost(host)
							}
						} else {
							self.findHost(host)
						}
					} else {
						let request = URLRequest(url: url)
						self.webView.load(request)
					}
					
					self.activeURL = url
					self.window?.makeFirstResponder(nil)
				}
			}
			return true
		}
		return false
	}
	
	// MARK: WKNavigationDelegate
	
	func webView(_ webView: WKWebView,
		     decidePolicyFor navigationAction: WKNavigationAction,
		     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
		if navigationAction.navigationType == .linkActivated {
			if var url = navigationAction.request.url {
				if url.host == nil {
					url = URL(string: url.path,
						  relativeTo: self.activeURL)!
				}
				
				self.URLTextField.stringValue = url.absoluteString
				self.window?.title = "Loading…"
				
				if url.scheme == "httpf" {
					var host = ""
					/* This adds support for emails potentially being used as identifiers. */
					if let user = url.user {
						host += user
						host += "@"
					}
					host += url.host!
					
					if let activeURL = self.activeURL {
						var activeHost = ""
						if let user = activeURL.user {
							activeHost += user
							activeHost += "@"
						}
						activeHost += activeURL.host!
						
						if activeHost == host {
							Networking.connectTo(host: self.activeURLHost!,
									     port: self.activeURLPort!)
						} else {
							self.findHost(host)
						}
					} else {
						self.findHost(host)
					}
					
					decisionHandler(.cancel)
				} else {
					decisionHandler(.allow)
				}
				
				self.activeURL = url
			}
			
			return
		}
		
		decisionHandler(.allow)
	}
	
	func webView(_ webView: WKWebView,
		     didFinish navigation: WKNavigation!) {
		if let title = webView.title {
			self.window?.title = title
		} else {
			self.window?.title = "Foam"
		}
	}
	
	// MARK: Methods
	
	@objc private func didCheckIn() {
		self.getLocalIdentifier()
	}
	
	@objc private func didConnectToServer(notification: NSNotification) {
		let hostData: Dictionary<String, Any> = notification.object as! Dictionary<String, Any>
		let host = hostData["host"]! as! String
		let port = UInt16(hostData["port"]! as! UInt16)
		
		if host == self.activeURLHost && port == self.activeURLPort {
			if let url = self.activeURL {
				self.fetchDocument(atPath: url.path)
			}
		}
	}
	
	@objc private func didFailToConnectToServer(notification: NSNotification) {
		let hostData: Dictionary<String, Any> = notification.object as! Dictionary<String, Any>
		let host = hostData["host"]! as! String
		let port = UInt16(hostData["port"]! as! UInt16)
		
		let alert = NSAlert()
		alert.messageText = "Could Not Reach Server"
		alert.informativeText = "The web server responded with the address \(host):\(port) but it is unreachable."
		alert.alertStyle = .critical
		alert.addButton(withTitle: "Okay")
		alert.runModal()
		
		if let title = webView.title {
			self.window?.title = title
		} else {
			self.window?.title = "Foam"
		}
	}
	
	@objc private func didReceiveLocalIdentifier(notification: NSNotification) {
		self.localIdentifier = notification.object as? String
	}
	
	@objc private func didReceiveProtocolMessage(notification: NSNotification) {
		let message: Message = notification.object as! Message
		let addressComponents = message.payload.components(separatedBy: [":"])
		self.activeURLHost = addressComponents[0]
		self.activeURLPort = UInt16(addressComponents[1])!
		
		Networking.connectTo(host: self.activeURLHost!,
				     port: self.activeURLPort!)
	}
	
	@objc private func didReceiveWebResponse(notification: NSNotification) {
		let htmlString = notification.object as! String
		print("HTML RESPONSE:\n\(htmlString)")
		self.webView.loadHTMLString(htmlString,
					    baseURL: self.activeURL!.baseURL)
	}
	
	private func fetchDocument(atPath path: String) {
		print("REQUEST PAGE \(path)")
		let request = "GET " + path
		let delimiter = "\r\n"
		
		Networking.sendWebData(request.data(using: .utf8)!)
		Networking.sendWebData(delimiter.data(using: .utf8)!)
		Networking.sendWebData(delimiter.data(using: .utf8)!)
	}
	
	private func getLocalIdentifier() {
		let message = [PROTO_KEY_LOCAL_IDENTIFIER: ""]
		Networking.send(message: message)
	}
	
	private func findHost(_ host: String) {
		if host.count == 0 {
			return
		}
		
		if let identifier = self.localIdentifier {
			print("Searching for host \"\(host)\"…")
			let service = "http"
			let message = ["to": service+"@"+host,
				       "body": identifier]
			Networking.send(message: message)
		} else {
			let alert = NSAlert()
			alert.messageText = "Could Not Complete Request"
			alert.informativeText = "The local identifier is still unavailable."
			alert.alertStyle = .critical
			alert.addButton(withTitle: "Okay")
			alert.runModal()
			
			self.window?.title = "Foam"
		}
	}
	
}
