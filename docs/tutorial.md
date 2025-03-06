# xTalk - Get Started

A [Nomicle](https://github.com/alimahouk/nomicle)-powered, inter-app messaging system. xTalk (pronounced "crosstalk") can be classified as a delay-tolerant communications network.

## Get Started

### Table of Contents

1. [Windows](#windows)
2. [macOS](#macos)
3. [Linux](#linux)

### Windows

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Open the Start menu, type "cmd", and launch Command Prompt.
   - In the Command Prompt window that appears, type "python". If you get an error, that means Python is either not installed or it hasn't been added to your PATH. Use your favourite web search engine to find out how to install Python 3 or how to add it to your PATH on Windows.

2. Assuming Python 3 is now running in your Command Prompt window, make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number) and that the [cryptography Python package](https://cryptography.io/en/latest/) is installed by following the instructions on the project's website. You may then quit Python by typing "quit()" and pressing the Return key.

3. [Download](https://github.com/noraco/xp002/releases) and [set up](https://github.com/noraco/xp002/blob/main/docs/tutorial.md#windows) Nomicle on your PC.

4. [Download the xTalk Complete Bundle for Windows](https://github.com/alimahouk/xtalk/releases) and extract it into a folder called `xTalk`. The final folder structure should look something like this:

   ```
   xTalk/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── xtalk.py
   ├── LICENSE
   └── start.bat
   ```

5. You are now ready to run xTalk on your computer. Double-click `start.bat`. This will start the Messenger as a background process (i.e. you won't see a window appear). *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the xTalk network.*

6. That's it! You're now all set to run xTalk-powered programs. xTalk runs in the background on your PC, and it is recommended that you leave it that way so long as your PC is running to allow xTalk-enabled apps to make use of it. xTalk also depends on Nomicle running in the background.

7. To stop xTalk at any time, launch Task Manager, find the Messenger (it'll appear as a Python process), and end the task.

#### Running on PC Startup

If you want xTalk to automatically start up every time you restart your PC…

1. You need to open the Startup folder. Press the Windows key + R. In the Run window that appears, type:

   ```
   shell:startup
   ```

2. Back in the xTalk folder, right-click `start.bat` and choose "Create shortcut", which will then create a new shortcut file.

3. Drag the shortcut file to the Startup folder in the other window.

If at any time you decide you don't want xTalk to start up with your PC, follow these steps to open the Startup folder and simply delete the shortcut to `start.bat`.

### macOS

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Use Spotlight search and type "terminal". Launch the Terminal app.
   - Inside Terminal, type "python3". If you get an error, that means Python is probably not installed. Use your favourite web search engine to find out how to install Python 3 on macOS.

2. Assuming Python 3 is now running in your Terminal window, make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number) and that the [cryptography Python package](https://cryptography.io/en/latest/) is installed by following the instructions on the project's website. You may then quit Python by typing "quit()" and pressing the Return key.

3. [Download](https://github.com/noraco/xp002/releases) and [set up](https://github.com/noraco/xp002/blob/main/docs/tutorial.md#macos) Nomicle on your Mac.

4. [Download the xTalk Complete Bundle for macOS/Linux](https://github.com/alimahouk/xtalk/releases) and extract it into a directory called `xTalk`. The final folder structure should look something like this:

   ```
   xTalk/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── LICENSE
   ├── start.sh
   ├── stop.sh
   └── xtalk.py
   ```

5. You are now ready to run xTalk on your Mac. In the Terminal window, you need to navigate to the xTalk directory you extracted. An easy way to do this is to type "cd " (there's a space after the "cd") and then drag the directory from Finder and drop it over the cursor inside Terminal. Terminal should insert the path to the directory at the cursor. Press the Return key.

6. Type the following (pressing the Return key after you enter each line; do not include the "$" character in what you type):

   ```bash
   sudo chmod u+x start.sh
   sudo chmod u+x stop.sh
   sudo chmod u+x xtalk.sh
   sudo ./start.sh
   ```

   You will be prompted to enter the password you use to log into your Mac after you enter the first line because "sudo" is a command that uses administrator privileges. *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the xTalk network.*

7. That's it! You're now all set to run xTalk-powered programs. xTalk runs in the background on your Mac, and it is recommended that you leave it that way so long as your Mac is running to allow xTalk-enabled apps to make use of it. xTalk also depends on Nomicle running in the background.

8. To stop xTalk at any time, follow the steps above to navigate to the xTalk directory and run the `stop.sh` script. Note that this will only work if you had started xTalk using `start.sh`, otherwise you need to kill the Messenger process yourself using Terminal or Activity Monitor.

#### Running on Mac Startup

xTalk requires elevated privileges to run on macOS because it writes to system directories (inside `/usr/local/`). A feature of macOS called System Integrity Protection won't allow xTalk to write to files at that location otherwise. When you restart your Mac, the easiest thing to do would be to run `$ sudo ./start.sh` yourself using Terminal. If you're feeling adventurous, tutorials exist online to show you how to run the script with elevated privileges. However, this guide is written with the goal of simplicity in mind, so such an exercise is left to the discretion of the reader.

### Linux

1. Download and install [Python 3](https://www.python.org/download/releases/3.0/) if you don't already have it installed. To find out:
   - Launch the terminal.
   - Inside the terminal, type "python3". If you get an error, that means Python is probably not installed. Use your favourite web search engine to find out how to install Python 3 on your Linux distro.

2. Assuming Python 3 is now running in your terminal window, make sure the displayed Python version number is of the form 3.x or 3.x.x (where "x" can be any number) and that the [cryptography Python package](https://cryptography.io/en/latest/) is installed by following the instructions on the project's website. You may then quit Python by typing "quit()" and pressing the Return key.

3. [Download](https://github.com/noraco/xp002/releases) and [set up](https://github.com/noraco/xp002/blob/main/docs/tutorial.md#linux) Nomicle on your computer.

4. [Download the xTalk Complete Bundle for macOS/Linux](https://github.com/alimahouk/xtalk/releases) and extract it into a directory called `xTalk`. The final folder structure should look something like this:

   ```
   xTalk/
   ├── PyNomicle/
   │   └── nomicle.py
   ├── LICENSE
   ├── start.sh
   ├── stop.sh
   └── xtalk.py
   ```

5. You are now ready to run xTalk on your computer. In the terminal window, you need to navigate to the xTalk directory you extracted. An easy way to do this is to type "cd " (there's a space after the "cd") and then drag the directory from your shell window and drop it over the cursor inside the terminal. The terminal should insert the path to the directory at the cursor (it's also possible your terminal app doesn't support this, in which case you need to either paste or type the path). Press the Return key.

6. Type the following (pressing the Return key after you enter each line; do not include the "$" character in what you type):

   ```bash
   sudo chmod u+x start.sh
   sudo chmod u+x stop.sh
   sudo chmod u+x xtalk.sh
   sudo ./start.sh
   ```

   You will be prompted to enter the password you use to log into your computer after you enter the first line because "sudo" is a command that uses administrator privileges. *If you get a firewall alert, make sure to allow it through otherwise you won't be able to connect to the xTalk network. **xTalk uses port 1993 by default so make sure to allow UDP traffic over that port number.***

7. That's it! You're now all set to run xTalk-powered programs. xTalk runs in the background on your computer, and it is recommended that you leave it that way so long as your computer is running to allow xTalk-enabled apps to make use of it. xTalk also depends on Nomicle running in the background.

8. To stop xTalk at any time, run the `stop.sh` script. Note that this will only work if you had started xTalk using `start.sh`, otherwise you need to kill the Messenger process yourself.

#### Running on Computer Startup

Follow the steps mentioned in [this Ask Ubuntu post](https://askubuntu.com/a/956539). The contents of your `rc.local` file should look something like:

```bash
#!/bin/sh -e
./replace/this/with/the/actual/path/to/start.sh
exit 0
```

You can check if this method works by running the following command in the terminal when you restart your computer:

```bash
ps aux | grep python
```

You should see the Messenger running as a Python process.
