#!/bin/sh
aosp=/mnt/extra/aosp
filename=EvMonitor.h
runtime_path=$aosp/art/runtime/$filename
jni_path=$aosp/frameworks/base/core/jni/$filename
sudo cp $runtime_path $jni_path