# Harness Source

## harness.h

The header file for the harness. Contains helper functions like `ConsumeBytes2Jint`. These functions consume bytes from the input bytes and return the corresponding Java object. The harness generator uses these functions to generate the harness.cpp

## harness_skeleton.cpp

The underlying harness skeleton. The input is read from a file. The harness generator uses the placeholders in BOLD to insert the relevant code for a specific function.

`./harness [APPNAME] [FOLDERNAME_MEMORYDUMPING] [PATHTOINPUTFILE]`

### Performance improvments

Since after the JVM creation, the page table has size ~600kB, forking is fairly slow leading to low fuzzing performance: ~80 execs/s for a simple example.
To remedy this we use a little hack that tries to minimize the size of the page table before forking. The intuition is that by unmapping memory and then remapping the same memory again, the page table size is shrunk. With this we are able to go back up to about ~300 execs/s. 

This hack takes place after allocating the callerobject and before initializing the AFL forkserver. We iterate over all memory regions and for all memory regions that have been newly created by the JVM we write the data in that memory region to a file. Then we unmap the memory region and then map it again with a file backed mmap.
To minimize the number of open file descriptors we use the same file to store the data for contiguos mappings.

Make sure to set a high enough value for `AFL_FORKSRV_INIT_TMOUT` since writing all the memory to disk takes a minute or two.

There is also a ignorelist for memoryregions so some regions which will either break our program or will for sure be accessed are not unmapped.

The allocated memory now has rwx permissions (higher performance) but the content is the same. Interestingly the overhead after forking for paging in memory is neglible...

There is definetly some room for improvement for this hack but at least for the [hellolibs app](https://github.com/HexHive/androlib-eval/tree/harness-unittest) native function everything works fine.

Problems encountered:

- JVM abort/crash -> check if the memory accessed had a special name beforehand, add to ignorelist
- crash in harness -> check the accessed memory, currently [libc:malloc] is in the ignorelist because some of the structures access this region.

**Improvments/Dials to turn:**

Add the original permissions to the memory regions (- 80/100 execs/s):

```c++
for(MemoryRegion memReg : memregs_unmapped){
            std::cout << "mapping: " << memReg.regionName << std::endl;
            if(prev_memreg_set2){
                if(prev_memreg2.fileName == memReg.fileName){
                    // reuse the previous file descriptor
                    mmap((void*)memReg.startAddress, memReg.size, memReg.permissions, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
                } else {
                    fd = open(memReg.fileName.c_str(), O_RDWR);
                    mmap((void*)memReg.startAddress, memReg.size, memReg.permissions, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
                }
            } else {
                fd = open(memReg.fileName.c_str(), O_RDWR);
                mmap((void*)memReg.startAddress, memReg.size, memReg.permissions, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
                prev_memreg_set2 = true;
            }
            prev_memreg2 = memReg;
```

Refine the ignorelist:

```c++
std::vector<std::string> ignorelist = {"[anon:scudo:secondary]", "[anon:scudo:primary]", "[anon:dalvik-non moving space]", "[anon:libc_malloc]", "[stack]", "[anon:cfi shadow]"};
```

- [anond:scudo...], heap used by the current implementation (in Android > 11)
- [anon:dalvik-non moving space], required for the alloc object call (and maybe some other calls) -> probably just needs a region named like this
- [anon:libc_malloc] is used for some strings in the memReg class, it may be possible to avoid this or ensure only the specific libc_malloc is not mapped
- unmapping the stack bricks the program
- [anon:cfi shadow]: not sure about unmapping the shadow stack
- currently we add the targetlibrary but we only do exact string matching on the ignorelist, TODO: implement substring matching on ignorelist

Unmap everything even stuff that was mapped previously just by the harness loading.

Instead of having the JVM load all these libraries, statically link them into the harness or create one big library blog exporting and implementing all the functions in all those .so files.

Further reduce gaps between libraries by having files bridge small gaps in the memory (fewer open fds and memory regions) *huge performance potential*

Android >11 uses scudo malloc, which is hardened malloc. Of course this mallo fractures the virtual address space. In the performance_gpixel branch I started working on an implementation that avoids allocations on the heap (to be able to unmap all other heap stuff, some of which may have been allocated by then JVM). Alternatively preload a libc without this hardened BS malloc.

If too many files are being written, then at some point libc tries to access some memory that was previously unmapped -> change implementation of file write. (But this is not an issue for normal operation)

Disable the watchdogdaemon (https://gist.github.com/kylin17/7a6397022b4ef5c284917b5305f05729)
POC code:
```c++
jclass WatchdogDameonClazz = env->FindClass("java.lang.Daemons$FinalizerWatchdogDaemon");
        jclass daemonClazz = env->FindClass("java.lang.Daemons$Daemon");
        jfieldID instanceField = env->GetFieldID(WatchdogDameonClazz, "INSTANCE", "L/java/lang/Daemons$FinalizerWatchdogDaemon");
        jmethodID daemonIsRunningMethod = env->GetMethodID(daemonClazz, "isRunning", "()Z");
        jobject watchdogDaemonInstance = env->GetObjectField(WatchdogDameonClazz, instanceField);
        jboolean isWatchdogDaemonRunning = (jboolean) env->CallBooleanMethod(watchdogDaemonInstance, daemonIsRunningMethod);
        if(isWatchdogDaemonRunning){
            jfieldID daemonThreadField = env->GetFieldID(daemonClazz, "thread", "L/java/lang/object");
            jobject daemonThreadInstance = env->GetObjectField(watchdogDaemonInstance, daemonThreadField);
            jmethodID daemonStopMethod = env->GetMethodID(WatchdogDameonClazz, "stop", "()");
            env->CallVoidMethod(daemonThreadInstance, daemonStopMethod);
        }
```

Execs/s start really high and then drop, CPU usage fairly low. Why?

## FuzzedDataProvider.h

Helper library from https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h to read in bytes and split them up.