LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := em_agent
LOCAL_SRC_FILES := em_agent.c
include $(BUILD_EXECUTABLE)