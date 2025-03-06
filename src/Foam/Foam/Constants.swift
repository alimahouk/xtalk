//
//  Constants.swift
//  Foam
//
//  Created by alimahouk on 25/08/2019.
//  Copyright © 2019 alimahouk. All rights reserved.
//

import Foundation

let NET_SERV_PORT: UInt16	= 1993
let NET_SERV_ADDR    		= "127.0.0.1"
let NET_SOCK_TIMEOUT		= 5

let PROTO_KEY_LOCAL_IDENTIFIER 	= "me"
let PROTO_KEY_PAYLOAD 		= "body"
let PROTO_KEY_SENDER 		= "from"
let PROTO_KEY_SERVICES 		= "interest"

enum PMEventNotification: String {
	case checkedIn				/* Called after connecting to the server and checking in. */
	case connectedToServer
	case disconnectedFromServer
	case failedToConnectToServer
	case receivedLocalIdentifier
	case receivedProtocolMessage
	case receivedWebResponse
	case sentProtocolMessage
}

struct Message {
	var sender: String
	var payload: String
}

/* Extend the Foundation NotificationCenter to support
* our custom notifications.
*/
extension NotificationCenter {
	
	func add(observer: Any,
		 selector: Selector,
		 notification: PMEventNotification,
		 object: Any? = nil) {
		addObserver(observer,
			    selector: selector,
			    name: Notification.Name(notification.rawValue),
			    object: object)
	}
	
	func post(notification: PMEventNotification,
		  object: Any? = nil,
		  userInfo: [AnyHashable: Any]? = nil) {
		post(name: NSNotification.Name(rawValue: notification.rawValue),
		     object: object,
		     userInfo: userInfo)
	}
	
}
