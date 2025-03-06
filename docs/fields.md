# xTalk - xTalk Message Fields

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](#xtalk-message-fields)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## xTalk Message Fields

- `address`: Used for IP address discovery (see [IP Address Discovery](ipdiscovery.md)).
- `body`: The main payload of a message. This can be an arbitrary string that is at most 140 characters in length.
- `from`: The message sender. This will always be variant of an xTalk address (see [xTalk Addresses](addressing.md)).
- `interest`: Used when registering interest in one or more SIDs for messages that an app is interested in receiving.
- `me`: Used for requesting the Nomicle identifier of the local machine (see [Getting the Local Nomicle Identifier](localidentifier.md)).
- `re`: The reference ID of the message being replied to.
- `ref`: The reference ID of a particular message.
- `status`: Used for following up on the status of a message (see [Following Up on the Status of a Message](followup.md)).
- `time`: The date and time that a message was sent by the app as a Unix timestamp.
