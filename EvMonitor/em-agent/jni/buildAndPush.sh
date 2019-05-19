#!/bin/bash
# Date: Mon May 20 00:53:57 2019
# Author: January

abi=arm64-v8a
name=em_agent
remote_path=/data/local/tmp

ndk-build
adb push ../libs/$abi/$name $remote_path

