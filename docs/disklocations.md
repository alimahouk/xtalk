# xTalk - Disk Locations of Interest

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](#disk-locations-of-interest)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## Disk Locations of Interest

These are the default locations of the following files. Keep in mind the user may choose to modify them.

### Hosts File

A text file containing a list of the IP addresses and port numbers of other known xTalk installations. A user may manually modify this file to add or remove IP addresses and port numbers as they wish. The Messenger also uses the broadcast address to discover other installations on its LAN.

- macOS and Linux: `/usr/local/var/xtalk/hosts`
- Windows: `%APPDATA%\xTalk\hosts.txt`
