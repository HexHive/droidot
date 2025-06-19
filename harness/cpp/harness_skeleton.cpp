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
#include "FuzzedDataProvider.h"


/*
Testing harness for frida mode
*/

char __my_dummy[65536] __attribute__((aligned(4096)));

/* target function definition */
extern "C"
{
	/***********************************/
	/* MODIFY TARGET FUNCTION DEF HERE */
	/***********************************/
GENERATOR_FUNCTIONDEFINTION
    __attribute__((visibility("default"))) void AddSpecialSignalHandlerFn() 
        { }
}


GENERATOR_GLOBALFUNCTIONS

void fuzz_one_input(uint8_t *buf, size_t buf_size) {

        FuzzedDataProvider fuzzed_data((uint8_t*)buf, buf_size);

        // Parse the input byte stream
GENERATOR_INPUTPARSING

		// call target function
GENERATOR_CALLINGTARGETFUNCTION

		_exit(0);
}

int main(int argc, char *argv[]) {
		/*
		As this part is only run after the afl.js preloading, we expect the following to be done
		1. targetLibBase global is set
		2. ART has been loaded
		3. unmapping and remapping has been done
		*/
		// get the targetFunction address
		if(afl_area_ptr == NULL){
			std::cerr << "[HARNESS] afl_area_ptr is 0" << std::endl;
			abort();
		}
		
		if(targetLibBase == 0){
			std::cerr << "[HARNESS] library base is 0" << std::endl;
			abort();
		}

GENERATOR_FUNCTIONOFFSETS

		if(!env){
			std::cerr << "env is 0" << std::endl;
			abort();
		}
		
		close(11);
		close(12);
		close(13);
		close(42);
		// Read in input file into memory
        uint8_t buffer[1048576];
        size_t buf_size = 1048576;
        fuzz_one_input(buffer, buf_size);
}
