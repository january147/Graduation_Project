#!/bin/sh
des=/data/local/tmp
frida=frida


# 放置必要文件
adb push $frida/frida.so $des
adb push $frida/frida64.so $des
adb push $frida/frida.config $des
adb push $frida/frida64.config $des
adb push $frida/explore.js $des
