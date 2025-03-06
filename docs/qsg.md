# xTalk - Quick Start Guide

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](#quick-start-guide)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## Quick Start Guide

The quickest and easiest way to get a feel for xTalk is through Telnet, which is a simple network communication tool available on most operating systems (you might have to download/enable it). First make sure Nomicle and xTalk [are running](tutorial.md). Launch Telnet from the command line, passing in the hostname (the computer running xTalk that you're trying to connect to, which in most cases is your own machine, `localhost`) and port number where xTalk is listening for connections (which is `1993` by default):

```bash
telnet localhost 1993
```

If everything is running correctly, Telnet will display a message that it has successfully connected.

### Sending a Message

xTalk can be used to send messages to apps running on the same computer or across the network to another computer. For the sake of simplicity, this guide will send a message to the same computer (sending a message to a different computer follows the exact same steps; the only difference is the recipient's xTalk address).

Type the following (press the Return key at the end of each line):

```
to: mytestservice
body: hello!
```

You need to press the return key a second time after typing the last line. This tells xTalk that you're done entering your message. You'll see the message's reference ID appear onscreen:

```
ref: fa27f2097e034550fd3f899ab91de7d65a9e5d049736004f2f6cb4035b98d22a
```

Normally, you can use this ID to check if your message has been delivered or if you want to reply to this specific message (which may be the case in a real scenario when your app receives a message from another app) but for this example, we can ignore it.

That's it! You've just sent your first xTalk message to the `mytestservice` service on your local machine, which is a random SID we just made up for this example. The next step is to receive the message we just sent.

### Receiving a Message

To receive a message, you need to register your interest with xTalk for the SIDs you wish to handle. We want to receive the test message we just sent in the previous section, so we'll register our interest for `mytestservice`. Open a new command line window and launch Telnet again:

```bash
telnet localhost 1993
```

Type the following (press the Return key twice at the end of the line):

```
interest: mytestservice
```

xTalk will return the following to indicate that your interest message was valid:

```
interest: 0
```

Within seconds, the message you sent earlier should appear onscreen:

```
from: alimahouk
ref: fa27f2097e034550fd3f899ab91de7d65a9e5d049736004f2f6cb4035b98d22a
time: 2020-11-03 13:48:22.089998
body: hello!
```

Hopefully you found that using xTalk is simple and easy. In most cases, people won't need to type messages manually like this. You can program your apps to send and receive them when you need to communicate over a network in a peer-to-peer manner.
