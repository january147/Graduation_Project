#!/bin/bash
# 该脚本从aosp项目中抽取EvMonitor相关文件

# source dir
# 设置aosp项目的根目录
aosp=/mnt/extra/aosp
art=$aosp/art/runtime
fcore=$aosp/frameworks/base/core/
android_app_java=$fcore/java/android/app
com_android_internal_os_java=$fcore/java/com/android/internal/os
fcore_jni=$fcore/jni

# source file
# 修改的Android源代码文件
art_method_cc=$art/art_method.cc
art_method_h=$art/art_method.h
interpreter_cc=$art/interpreter/interpreter.cc
dex_file_cc=$art/dex_file.cc
zygote_java=$com_android_internal_os_java/Zygote.java
activity_thread_java=$android_app_java/ActivityThread.java
zygote_cpp=$fcore_jni/com_android_internal_os_Zygote.cpp

# 添加的代码文件
EvMonitor_h=$art/EvMonitor.h
EvMonitor_cc=$art/EvMonitor.cc

# cp to current dir
files=($art_method_cc $art_method_h $interpreter_cc $dex_file_cc $EvMonitor_h $EvMonitor_cc $zygote_java $activity_thread_java $zygote_cpp)
for file in ${files[*]}
do
    cp $file ./sourcecode/
done



