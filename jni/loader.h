#ifndef __LOADER_H__
#define __LOADER_H__

#include <jni.h>

void* ldopen(const char* filename, int flags);
void* ldsym(void* handle, const char* symbol);
int ldclose(void* handle);

typedef int (*JNI_CreateJavaVM_Type)(JavaVM**, JNIEnv**, void*);
typedef int (*fJNI_OnLoad)(JavaVM* vm, int n);

#endif
