# xTalk - Bootstrap Servers

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Bootstrap Servers

Bootstrap servers are computers running xTalk with public IP addresses that new xTalk installations can use to discover other xTalk nodes and help integrate them into the network. To use these servers, copy and paste any one or two of these addresses into your xTalk `hosts` file (located by default at `/usr/local/var/xtalk/hosts` on macOS/Linux and `%APPDATA%\xTalk\hosts.txt` on Windows); make sure each address in the file is on a line of its own.

- 35.176.210.85:1993

At the moment, the only publicly known bootstrap server is the one hosting this website. If you have a computer running xTalk that is online for long periods of time and would like to help grow the xTalk network, send us your computer's IP address and the port you've mapped to xTalk.
