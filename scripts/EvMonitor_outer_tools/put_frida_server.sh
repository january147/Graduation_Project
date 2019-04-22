#!/bin/sh
des=/data/local/tmp
file=frida_server
adb push $file $des
adb shell chmod 755 $des/$file
