#!/bin/sh
des=/data/local/tmp

adb push frida.so $des
adb push frida64.so $des
adb push frida.config $des
adb push frida64.config $des
adb push explore.js $des
adb shell setenforce 0