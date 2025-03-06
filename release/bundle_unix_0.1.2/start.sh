# start.sh | v0.1 | 1/10/2020 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is a convenience script to start xTalk.
#
# On Unix-like systems (macOS, specifically), you may
# need to use sudo to execute this script.

# Redirect program output as required; default is no output.
# The PID of the process is written to /tmp.

FILE_XTALK=xtalk.py
if [ -f "$FILE_XTALK" ]; then
        nohup python3 xtalk.py </dev/null >/dev/null 2>&1 & echo $! > /tmp/xtalk.pid
fi
