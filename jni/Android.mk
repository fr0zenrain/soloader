LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm
LOCAL_MODULE:= soloader

LOCAL_SRC_FILES:=   \
    dlfcn.cpp \
    linker.cpp \
    linker_phdr.cpp \
    main.cpp
    

LOCAL_CFLAGS += -g  -O2 -DANDROID_ARM_LINKER -fpermissive -fvisibility=hidden 

# We need to access Bionic private headers in the linker.
LOCAL_CFLAGS += -I$(LOCAL_PATH)/../libc/ -I$(LOCAL_PATH)/../libc/include 
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_NO_CRT := true

include $(BUILD_EXECUTABLE)
