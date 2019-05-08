#!/bin/sh
adb root
sleep 1
adb shell setenforce 0
./set_target.sh

