# xTalk - Getting the Local Nomicle Identifier

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](#getting-the-local-nomicle-identifier)
- [IP Address Discovery](ipdiscovery.md)

## Getting the Local Nomicle Identifier

An app may either read the Nomicle identity file for itself or it may request it from the Messenger:

```
me
```

Response:

```
me: bob
```
