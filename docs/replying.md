# xTalk - Replying to a Specific Message

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](followup.md)
- [Replying to a Specific Message](#replying-to-a-specific-message)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## Replying to a Specific Message

Your application may choose to send a message in reply to a specific message. This extra field is simply a convenience for apps and bears no semantic meaning to the Messenger (i.e. the Messenger does no verification to check if the message being replied to actually exists). You may reply to a message like so:

```
to: telnet@bob
re: 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
body: Thank you for the birthday wishes.
```

The string value in the 're' field is the identifier of the message you are replying to.
