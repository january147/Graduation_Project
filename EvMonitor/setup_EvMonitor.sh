#!/bin/bash

adb root
# 关闭selinux, selinux会阻止app读取/data/local/tmp下的文件
adb shell setenforce 0

# 传输frida到手机端的/data/local/tmp目录下
./EvMonitor_utils/put_frida.sh
# 传输EvMonitor_agent到/data/local/tmp目录下
./em_agent/buildAndPush.sh