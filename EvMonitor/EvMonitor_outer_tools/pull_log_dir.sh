#!/bin/bash

app="com.january147"
if [[ $# > 1 ]]; then
    app=$1
fi
log_dir=/data/data/$app/log_dir
adb pull $log_dir ./extra/