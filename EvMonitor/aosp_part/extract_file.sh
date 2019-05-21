#!/bin/bash

# source dir
aosp=/mnt/extra/aosp
art=$aosp/art/runtime
fcore=$aosp/frameworks/base/core/
android_app_java=$fcore/java/android/app
com_android_internal_os_java=$fcore/java/com/android/internal/os
fcore_jni=$fcore/jni

# source file
art_method_cc=$art/art_method.cc
art_method_h=$art/art_method.h
dex_file_cc=$art/dex_file.cc
Evmonitor_h=$art/EvMonitor.h

zygote_java=$com_android_internal_os_java/Zygote.java

activity_thread_java=$android_app_java/ActivityThread.java
zygote_cpp=$fcore_jni/com_android_internal_os_Zygote.cpp

# cp to current dir
files=($art_method_cc $art_method_h $dex_file_cc $Evmonitor_h $zygote_java $activity_thread_java $zygote_cpp)
for file in ${files[*]}
do
    cp $file ./sourcecode/
done



