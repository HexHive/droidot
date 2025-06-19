#include <iostream>
#include <string>
#include <regex>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <fstream>
#include <dlfcn.h>
#include <jni.h>
#include <filesystem>
#include <climits>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

#include "libharness.h"

namespace fs = std::filesystem;

JavaVM *javaVM;
JNIEnv *env;
std::string targetAppPath;
std::string memoryPath;
std::string targetLibName;
long targetLibBase = 0;
void** afl_area_ptr = NULL;
std::string className0;
jclass CallerCls0;
jobject CallerObj0;

void set_afl_area_ptr(long ptr){
    afl_area_ptr = (void**) ptr;
}

void set_targetAppPath(std::string str){
    targetAppPath = str;
}

void set_memoryPath(std::string str){
    memoryPath = str;
}

void set_targetLibName(std::string str){
    targetLibName = str;
}

void set_targetLibBase(long base){
    targetLibBase = base;
}

void set_class0Name(std::string str){
    className0 = str;
}

std::vector<std::string> get_ignoreList(){
    std::vector<std::string> ignorelist = {"libharness.so", "libc++_shared.so", "libc.so", "harness", "afl-frida-trace.so", "/dev/binder", "[anon:scudo:primary]", "[anon:scudo:secondary]", "[anon:dalvik-non moving space]", "[anon:libc_malloc]", "[stack]", "[anon:cfi shadow]"};
    return ignorelist;
}

bool endsWith(const std::string& str, const std::string& ending) {
    if (ending.length() > str.length()) {
        return false;
    }
    return str.substr(str.length() - ending.length()) == ending;
}

bool in_ignoreList(std::string regionName){
    std::vector<std::string> ignorelist = get_ignoreList();
    if(regionName.size() == 0){
        // no unmapping of anynomous pages
        return true;
    }
    for (const std::string& ignore : ignorelist) {
        if (endsWith(regionName, ignore)) {
            return true;
        }
    }
    return false;
}

bool write_file_binary (std::string const & filename, 
  char const * data, size_t const bytes)
{
  std::ofstream b_stream(filename, 
    std::ios_base::app | std::fstream::binary);
  if (b_stream)
  {
    b_stream.write(data, bytes);
    return (b_stream.good());
  }
  return false;
}

/* Load android runtime using JNI functions */
void load_art()
{
	/* Set-up required arguments */
	std::string apk_path = "-Djava.class.path=" + targetAppPath + "/base.apk";
	//std::string apk_path = "-Djava.class.path=" + targetAppPath;
	std::string lib_path = "-Djava.library.path=" + targetAppPath + "/lib/arm64-v8a";
    JavaVMOption opt[] = {
    	{ apk_path.c_str(), nullptr},
        { lib_path.c_str(), nullptr}
    };


    JavaVMInitArgs args = {
        JNI_VERSION_1_6,
        std::size(opt),
        opt,
        JNI_FALSE
    };

	/* Open shared libraries */
    void * libart = dlopen("libart.so", RTLD_NOW);
    if (!libart) 
    {
        std::cerr << dlerror() << std::endl;
        abort();
    }

    void * libandroidruntime = dlopen("libandroid_runtime.so", RTLD_NOW);
    if (!libart) 
    {
        std::cerr << dlerror() << std::endl;
        abort();
    }
    
    auto JNI_CreateJavaVM = (JNI_CreateJavaVM_t *)dlsym(libart, "JNI_CreateJavaVM");
	
    if (!JNI_CreateJavaVM)
    {
        std::cerr << "No JNI_CreateJavaVM: " << dlerror() << std::endl;
        abort();
    }

    auto registerNatives = (registerNatives_t *)dlsym(libandroidruntime, "registerFrameworkNatives");
   	

    if (!registerNatives)
    {
        std::cerr << "No registerNatives: " << dlerror() << std::endl;
        abort();
    }

	/* Create JVM and register defaults native methods */
    std::pair<JavaVM *, JNIEnv *> ret;
	
    int res = JNI_CreateJavaVM(&ret.first, &ret.second, &args);
    if (res != 0)
    {
        std::cerr << "Failed to create VM: " << res << std::endl;
        abort();
    }

    javaVM = ret.first;
    env = ret.second;

    jint res1 = registerNatives(env, 0);
    if (res1 != 0)
    {
        std::cerr << "Failed to call registerNatives: " << res1 << std::endl;
        abort();
    }

    return;
}

/*
Reads /proc/self/maps and returns the base address of the library
*/
long readMapsBase(std::string targetLibName){
	std::ifstream infile( "/proc/self/maps" );
	std::string sLineIn = "";
	while(std::getline(infile, sLineIn))
    {
        if( sLineIn.find(targetLibName) != std::string::npos )
        {
            return std::stol( sLineIn.substr(0, sLineIn.find("-")), nullptr, 16 );
        }
    }
	return -1;
}

/*
Read the env variable ANDROLIB_MEMORY= and ANDROLIB_APP_PATH= and write the values to the globals
Also load the targetLibrary and set the offset
*/
void hack_env_init(){
    std::string memory_path = std::getenv("ANDROLIB_MEMORY");
    std::string app_path = std::getenv("ANDROLIB_APP_PATH");
    std::string lib_name = std::getenv("ANDROLIB_TARGET_LIBRARY");
    std::string class_name = std::getenv("ANDROLIB_CLASS0");
    set_memoryPath(memory_path);
    set_targetAppPath(app_path);
    set_targetLibName(lib_name);
    set_class0Name(class_name);
    fs::path dir = memoryPath;
    fs::remove_all(dir);
    fs::create_directory(dir);
}

/*
Load the target Library and get the base address of the library
*/
void load_targetLibrary(){
    void *lib = dlopen(targetLibName.c_str(), RTLD_NOW);
	if (!lib) 
	{
		std::cerr << dlerror() << std::endl;
		abort();
	}
    set_targetLibBase(readMapsBase(targetLibName));
    JNI_OnLoad_t *JNI_OnLoadPtr;
    JNI_OnLoadPtr = (JNI_OnLoad_t *)dlsym(lib, "JNI_OnLoad");
	if (JNI_OnLoadPtr)
	{
		JNI_OnLoadPtr(javaVM, NULL);
	}
}

/*
load the class0 object
*/
void load_class0_object(){
    printf("env: %p\n", env);
    std::cout << className0;
    CallerCls0 = env->FindClass(className0.c_str());
    printf("found class: %p\n", CallerCls0);
	CallerObj0 = env->AllocObject(CallerCls0);
    printf("alloced: %p\n", CallerObj0);
}


void readMaps_before(){
    std::ifstream  src("/proc/self/maps", std::ios::binary);
    std::ofstream  dst("./maps_start",   std::ios::binary);

    dst << src.rdbuf();
}


/*
Reads /proc/self/maps and stores them in a list of MemoryRegion objects
*/
std::vector<MemoryRegion> readMaps(std::string fileName){
    std::vector<MemoryRegion> out = {};
	std::ifstream infile( fileName );
	std::string sLineIn = "";
    int count = 0;
	while(std::getline(infile, sLineIn))
    {   
        MemoryRegion memReg;
        memReg.startAddress = std::stol( sLineIn.substr(0, sLineIn.find("-")), nullptr, 16 );
        memReg.endAddress = std::stol( sLineIn.substr(sLineIn.find("-")+1, sLineIn.find(" ")), nullptr, 16 );
        if(sLineIn.at(sLineIn.size()-1) == ']'){
            memReg.regionName = sLineIn.substr(sLineIn.rfind("["), sLineIn.length());
        } else {
            memReg.regionName = sLineIn.substr(sLineIn.rfind(" ")+1, sLineIn.length());
        }
        memReg.size = memReg.endAddress - memReg.startAddress;
        memReg.fileName = memoryPath + "/" + std::to_string(count);
        int permInd = sLineIn.find_first_of(" ")+1;
        memReg.setPermissions(sLineIn.substr(permInd, 4));
        out.push_back(memReg);
        count++;
    }
	return out;
}


void performance_hack(){
/*
    Unmap memory and remap rwx with file backed memory (to shrink the page table)
    150 kB pagetable (from 600kB) -> 100 execs/s
    all pages rwx + 80 execs per second on simple example
    */
    std::vector<MemoryRegion> memregs_before_JVM = readMaps("./maps_start");
    std::vector<MemoryRegion> memregs_after_JVM = readMaps("/proc/self/maps");
    std::vector<MemoryRegion> memregs_unmapped = {};
    MemoryRegion prev_memreg;
    bool prev_memreg_set = false;
    // experimental unmap everything new and then remapt with a file descriptor mapping
    for(MemoryRegion memReg2 : memregs_after_JVM){
        bool do_unmap = true;
        for(MemoryRegion memReg1 : memregs_before_JVM){
            if(memReg1.startAddress == memReg2.startAddress && memReg1.endAddress == memReg2.endAddress){ 
                std::cout << "keeping (initial memrange): " << memReg2.regionName << " start: " << std::hex << memReg2.startAddress << std::endl;
                do_unmap = false;
                prev_memreg_set = false;
                break;
            }
        }   
        // check against the ignorelist
        if(in_ignoreList(memReg2.regionName)){
        //if (std::count(ignorelist.begin(), ignorelist.end(), memReg2.regionName)){
            std::cout << "keeping (ignorelist): " << memReg2.regionName << " start: " << std::hex << memReg2.startAddress << std::endl;
            do_unmap = false;
            prev_memreg_set = false;
        }
        // the memory region should be unmapped
        if(do_unmap){
            if(!is_mmaped((void*)memReg2.startAddress, memReg2.size)){
                std::cout << "tried unmapping an unmapped region!" << std::endl;
                continue;
            }
            if(prev_memreg_set){
                if(prev_memreg.endAddress == memReg2.startAddress){
                    // the two regions are adjacent
                    // set the same filename
                    memReg2.fileName = prev_memreg.fileName;
                    memReg2.offset = prev_memreg.offset + prev_memreg.size;
                } 
            }
            prev_memreg = memReg2;
            prev_memreg_set = true;
            std::cout << "unmapping: " << memReg2.regionName << " start: " << std::hex << memReg2.startAddress << std::endl;
            if(memReg2.permissions == 0){
                // non accessible memory region, use truncate to quickly pad out the file
                int fd_nonwrit = open(memReg2.fileName.c_str(), O_RDWR | O_APPEND | O_CREAT, 0777);
                std::ifstream file_nonwrit(memReg2.fileName, std::ios::binary | std::ios::ate);
                size_t size_nonwrit = file_nonwrit.tellg();
                ftruncate(fd_nonwrit, memReg2.size + size_nonwrit);
                munmap((void*)memReg2.startAddress, memReg2.size);
                memregs_unmapped.push_back(memReg2);
                continue;
            }
            if (memReg2.permissions % 2 == 0){
                // nonreadable memory region, make readable just to be able to read it to file
                mprotect((void*)memReg2.startAddress, memReg2.size, PROT_READ);
            }
            bool status = write_file_binary(memReg2.fileName, (char*)memReg2.startAddress, memReg2.size);
            if(!status){
                std::cerr << "failed to dump memory!" << std::endl;
                abort();
            }
            munmap((void*)memReg2.startAddress, memReg2.size);
            // map pages with same permissions as before
            memregs_unmapped.push_back(memReg2);
        } 
    }
    MemoryRegion prev_memreg2;
    bool prev_memreg_set2 = false;
    int fd = -1;
    // remap all the previously unmapped memory
    for(MemoryRegion memReg : memregs_unmapped){
        std::cout << "mapping: " << memReg.regionName << " start: " << std::hex << memReg.startAddress <<std::endl;
        if(prev_memreg_set2){
            if(prev_memreg2.fileName == memReg.fileName){
                // reuse the previous file descriptor
                mmap((void*)memReg.startAddress, memReg.size, 7, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
            } else {
                fd = open(memReg.fileName.c_str(), O_RDWR);
                mmap((void*)memReg.startAddress, memReg.size, 7, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
            }
        } else {
            fd = open(memReg.fileName.c_str(), O_RDWR);
            mmap((void*)memReg.startAddress, memReg.size, 7, MAP_PRIVATE | MAP_FIXED, fd, memReg.offset);
            prev_memreg_set2 = true;
        }
        prev_memreg2 = memReg;
    }
}

int is_mmaped(void *ptr, size_t length) {
    FILE *file = fopen("/proc/self/maps", "r");
    char line[1024];
    int result = 0;
    while (!feof(file)) {
        if (fgets(line, sizeof(line) / sizeof(char), file) == NULL) {
            break;
        }
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
            continue; // could not parse. fail gracefully and try again on the next line.
        }
        unsigned long ptri = (long) ptr;
        if (ptri >= start && ptri + length <= end) {
            result = 1;
            break;
        }
    }
    fclose(file);
    return result;
}