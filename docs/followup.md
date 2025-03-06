# xTalk - Following Up on the Status of a Message

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Developer Documentation

### Table of Contents

- [Quick Start Guide](qsg.md)
- [Disk Locations of Interest](disklocations.md)
- [xTalk Addresses](addressing.md)
- [Connecting to xTalk & Messaging](connecting.md)
- [xTalk Message Fields](fields.md)
- [Following Up on the Status of a Message](#following-up-on-the-status-of-a-message)
- [Replying to a Specific Message](replying.md)
- [Getting the Local Nomicle Identifier](localidentifier.md)
- [IP Address Discovery](ipdiscovery.md)

## Following Up on the Status of a Message

To follow up on whether a message you've sent has been sent or delivered yet, you send the following message:

```
status: 81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9
```

The string passed in is the identifier of the message (you would have needed to retain it after the Messenger returned it when you sent the original message) whose status you are inquiring about. The Messenger responds with one of the following integer values:

- **1**: The message is still pending. This means the Messenger is still waiting for the nomicle of the recipient to show up in the Nomicle repository.
- **2**: The message was successfully sent but has yet to reach its recipient.
- **3**: The message was received by the recipient.

Example response:

```
status: 2
```
