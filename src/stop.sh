# stop.sh | v0.1 | 1/10/2020 | by alimahouk
# ---------------------------------------------
# ABOUT THIS FILE
# ---------------------------------------------
# This is a convenience script to kill xTalk.
# 
# On Unix-like systems (macOS, specifically), you may
# need to use sudo to execute this script.

PIDFILE_XTALK=/tmp/xtalk.pid
if [ -f "$PIDFILE_XTALK" ]; then
        kill -15 $(cat $PIDFILE_XTALK)
        rm $PIDFILE_XTALK
fi
