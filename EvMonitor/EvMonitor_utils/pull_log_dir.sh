#!/bin/bash
# 从指定app中抽取EvMonitor的日志文件夹, 保存在当前目录下的extra目录中

# 设置目标app包名
app="unknown"
# log文件夹路径
log_dir=/data/data/$app/log

if [[ $# > 1 ]]; then
    app=$1
fi

adb pull $log_dir ./extra/