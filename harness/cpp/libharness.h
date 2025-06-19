#include <iostream>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <stdlib.h> 
#include <sys/mman.h>
#include <cstdlib>
#include <dlfcn.h>
#include <jni.h>
#include <filesystem>

#include "FuzzedDataProvider.h"

extern "C"
{
	// types needed by harness
    typedef int JNI_CreateJavaVM_t(void *, void *, void *);
    typedef jint registerNatives_t(JNIEnv *, jclass);
    typedef jint JNI_OnLoad_t(JavaVM *, void *);

	// empty AddSpecialSignalHandlerFn function is necessary
	// It is something libsigchain appears to require. If the function isn’t present it aborts the process
    //_attribute__((visibility("default"))) void AddSpecialSignalHandlerFn() 
    //{ }
}

class MemoryRegion{
    public:
        unsigned long startAddress;
        unsigned long endAddress;
        size_t size;
        std::string regionName;
        std::string fileName;
        unsigned int permissions = 0x0;
        size_t offset = 0;
        void setPermissions(std::string perms) {
            if(perms.find('r')!= std::string::npos){
                permissions += 0x1;
            }
            if(perms.find('w')!= std::string::npos){
                permissions += 0x2;
            }
            if(perms.find('x')!= std::string::npos){
                permissions += 0x4;
            }
    }
};


#ifndef libharness_h__
#define libharness_h_
extern void load_art();
extern long readMapsBase(std::string targetLibName);
//long readMapsBase(std::string target);
extern auto SplitInput(const uint8_t *Data, size_t Size,
                                     const uint8_t *Separator,
                                     size_t SeparatorSize) -> std::vector<std::vector<uint8_t>>;
extern std::vector<MemoryRegion> readMaps(std::string file);
extern void hack_env_init();
extern void set_targetAppPath(std::string str);
extern void set_memoryPath(std::string str);
extern void set_targetLibName(std::string str);
extern void set_targetLibBase(long base);
extern void set_class0Name(std::string str);
extern void set_afl_area_ptr(void* ptr);
extern void readMaps_before();
extern void load_targetLibrary();
extern void load_class0_object();
extern void frida_setup_fuzzing();
extern bool endsWith(const std::string& str, const std::string& ending);
extern int is_mmaped(void *ptr, size_t length);
extern void performance_hack();
extern std::vector<std::string> get_ignoreList();
extern JavaVM *javaVM;
extern JNIEnv *env;
extern std::string targetAppPath;
extern std::string targetLibName;
extern long targetLibBase;
extern void** afl_area_ptr;
extern std::string memoryPath;
extern jclass CallerCls0;
extern std::string className0;
extern jobject CallerObj0;
#endif
