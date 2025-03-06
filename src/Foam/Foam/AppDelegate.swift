//
//  AppDelegate.swift
//  Foam
//
//  Created by alimahouk on 25/08/2019.
//  Copyright © 2019 alimahouk. All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
	
	public var net: Networking = Networking.shared	/* Store references to singletons that require NotificationCenter. */
	@IBOutlet weak var windowController: MainWindowController!
	@IBOutlet weak var window: NSWindow!


	func applicationDidFinishLaunching(_ aNotification: Notification) {
		Networking.connect()
	}

	func applicationWillTerminate(_ aNotification: Notification) {
		// Insert code here to tear down your application
	}
}
