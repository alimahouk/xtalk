# xTalk - IP Address Discovery

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
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](#ip-address-discovery)

## IP Address Discovery

One expected usage of xTalk will likely be the exchange of IP addresses to allow apps on different machines to connect directly to one another in a peer-to-peer fashion. Public IP address discovery typically requires the use of STUN/TURN. Since xTalk is likely to have already established its own P2P network, a node can ask one of its peers for its own public IP address. An app can request that address from the Messenger, like so:

```
address
```

The Messenger will respond with the machine's public IP address as well as its private address on the LAN, if one exists, separated by commas:

```
address: 10.21.97.88,192.0.1.1
```

Port mapping, however, is left to the app or the network administrator.
