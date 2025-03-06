# xTalk - Connecting to xTalk & Messaging

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](#connecting-to-xtalk--messaging)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## Connecting to xTalk & Messaging

The first step is to make sure the Messenger is running. From your application, you create a new TCP socket and connect to 127.0.0.1 at port 1993. What happens next depends on whether your app is interested in sending and/or receiving messages.

### Sending a Message

Sending a message requires three elements: a recipient, a service identifier, and a message string. The recipient and/or SID may be omitted in some scenarios (See [xTalk Addresses](addressing.md)). You write the following to your socket:

```
to: someservice@bob
body: Hello, bob!
```

To send a message to the wildcard service, do it like so:

```
to: @bob
body: This is a generic message.
```

Each field of a message is delimited by a carriage return followed immediately by a line feed. The end of the message is indicated by a double instance of \r\n. Once you have written the above text to your socket, the Messenger will reply with the new identifier generated for that message, which your app may retain:

```
ref: 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
```

You may use this reference ID for either of two things:

- Following up on the status of a message to know whether it has been delivered or not (see [Following Up on the Status of a Message](followup.md)).
- Creating message threads by replying to a specific message (see [Replying to a Specific Message](replying.md)).

### Receiving a Message

To receive messages, your app needs to register what services it is interested in handling with the Messenger. You register by passing in one or more SIDs as a comma-separated list:

```
interest: telnet, http
```

To receive messages sent without an SID specified (i.e. `to: @someone`), you use the special '*' SID. This is the wildcard SID used for generic messages. Do not confuse this with meaning 'I want to handle any and all inbound messages, regardless of their SID'.

```
interest: *
```

You may also include '*' as part of a list of other SIDs:

```
interest: telnet, *, http
```

Every time you send an 'interest' message, the SIDs you provide will overwrite any previous interests you registered. The Messenger will reply with '0' if the registration was successful or '-1' if an error occurred:

```
interest: 0
```

When a message arrives for one of your registered SIDs, your app will receive it in format similar to the following:

```
from: ali
ref: 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
time: 2020-02-06 22:52:01
body: Call me when you receive this.
```

If this message was in reply to one you sent earlier, the `re` field will be included with its identifier:

```
from: ali
ref: 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
re: 8bea037d6e1cadf853d712f075fe52f471eca1a736c5ef5273fd7708e10fb571
time: 2020-02-06 22:52:01
body: Call me when you receive this.
```

A message is considered delivered as soon as any running app on the machine receives it. If your app is not running and a different app receives a message for a service your app handles, your app will not receive that message the next time it runs. If messages for a service are still undelivered, your app will receive them as soon as it registers its interest for that service.
