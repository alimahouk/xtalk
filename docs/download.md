# xTalk - Downloads

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Downloads

xTalk is written in Python and has been successfully tested on Windows, macOS, and Linux. The xTalk command line tool currently only builds and runs on Unix-like systems (macOS and Linux).

### Prerequisites

xTalk has a few dependencies that you need to install on your system before you can get it to run. The Messenger requires [Python 3](https://www.python.org/download/releases/3.0/), the [cryptography Python package](https://cryptography.io/en/latest/), and [PyNomicle](https://github.com/alimahouk/nomicle/releases). Ideally, you would want to be running a full Nomicle installation to make the most of xTalk.

The xTalk command line tool requires a C compiler to build from source.

### Download Options

#### [The Complete Bundle (Windows)](https://github.com/alimahouk/xtalk/releases/download/v0.1.2/bundle_win_0.1.2.zip)

The Messenger (`xtalk.py`) + `PyNomicle` + a shell script that you can invoke to start the system as background processes (no Windows script currently exists for stopping xTalk; contributions welcome for a Windows version of a stop script).

#### [The Complete Bundle (macOS/Linux)](https://github.com/alimahouk/xtalk/releases/download/v0.1.2/bundle_unix_0.1.2.zip)

The Messenger (`xtalk.py`) + `PyNomicle` + two shell scripts that you can invoke to start/stop the system as a background process.

#### [Messenger](https://github.com/alimahouk/xtalk/blob/main/xtalk.py)

This program is the core component of xTalk.

#### [Command Line Adapter](https://github.com/alimahouk/xtalk/blob/main/xtalk.c)

This utility acts as a wrapper for standard Unix commands that output text. It reads from standard input and sends it to xTalk. The code currently only compiles on Unix-like systems. Changes are needed to support the Winsock API.

### Additional Resources

- [Browse](https://github.com/alimahouk/xtalk) the entire code repository
- [Read the guide](tutorial.md) to help you get started after you download the programs

### For App Developers

You'll find the [developer documentation](.) to be a valuable resource.
