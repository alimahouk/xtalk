# xTalk - xTalk Addresses

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](#xtalk-addresses)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## xTalk Addresses

### Service Identifiers (SIDs)

SIDs are arbitrary, case-insensitive strings and entirely convention-based. They allow apps to indicate what their message is all about in order for apps on the receiving end to know whether they should attempt to parse it or not. The only restriction is that they must not contain spaces, '@', '*', or ',' (comma) characters anywhere within them. Anyone can come up with their own SID to use in their own apps. Examples of generic SIDs might be 'mail', 'http', 'ftp', 'telnet', etc.

xTalk addresses should generally adhere to the format `service@user`. The part before the '@' symbol is the service identifier (SID), while the part after the '@' symbol is the user's Nomicle identifier. Since multiple apps might be simultaneously interested in the same SID(s), the same incoming message will be delivered to all those app instances.

### The Wildcard Service

A special *wildcard* service exists for generic messages that are not intended for any specific purpose. To send a message to the wildcard service, use the special '*' character:

```
*@user
```

### Address Variations

In the case of the wildcard service, the '*' may be omitted and still achieve the same effect:

```
@user
```

The `@user` part may be omitted, in which case the user is assumed to be the local machine:

```
some_service
```

It's even possible to send a message without specifying a recipient at all, which is interpreted as sending a wildcard message to the local user.
