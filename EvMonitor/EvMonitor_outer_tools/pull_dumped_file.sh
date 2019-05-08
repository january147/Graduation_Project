#!/bin/bash

app="top.january147.noticer"
if [[ $# > 1 ]]; then
    app=$1
fi
dumped_file_dir=/data/data/$app/dumped_file
adb pull $dumped_file_dir ./extra/