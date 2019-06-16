#!/bin/bash
# Date: Mon May 20 00:53:57 2019
# Author: January

abi=arm64-v8a
name=em_agent
config=em.config
remote_path=/data/local/tmp

# 需要ndk-build命令可用
ndk-build
adb push ../libs/$abi/$name $remote_path
adb push $config $remote_path

