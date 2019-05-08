#!/bin/sh
des=/data/local/tmp
adb push valgrind.sh $des
adb shell chmod 4755 $des/valgrind.sh
