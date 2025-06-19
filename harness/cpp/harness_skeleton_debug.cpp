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

namespace fs = std::filesystem;



/*
Harness skeleton for the harness generation with harness_generator.py
*/


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


/* globals definitions */
GENERATOR_GLOBALFUNCTIONS


void fuzz_one_input(uint8_t *buf, size_t buf_size) {
        FuzzedDataProvider fuzzed_data((uint8_t*)buf, buf_size);

        // Parse the input byte stream
GENERATOR_INPUTPARSING

        /* Call target function -- Fuzz */
		std::cout << "CALLING..." << std::endl;

GENERATOR_CALLINGTARGETFUNCTION

		_exit(0);
}

int main(int argc, char *argv[]) {
		/* Check parameters*/
		if (argc != 4) {
			std::cerr << "Error calling harness: 3 parameters are needed! (input file, do_memdump(1/0), do_fork(1/0))" << std::endl;
			return 1;
		}

        close(11);
		close(12);
		close(13);
		close(42);

		/* setup the memregs_before_JVM */
		readMaps_before();
    	/* Get target app path (e.g. target_APK/app_name) */
		std::string do_memdump = std::string(argv[2]);
        std::string do_fork = std::string(argv[3]);

		// setup everything via libharness.so
		hack_env_init();
		load_art();
		load_targetLibrary();
		load_class0_object();

GENERATOR_FUNCTIONOFFSETS

		if(do_memdump == "1"){
			performance_hack();
		}

		if(!env){
			std::cerr << "env is 0" << std::endl;
			abort();
		}

		if(do_fork == "1"){
            /* for, parent waits */
            int status = 0;
            pid_t pid = fork();
            if (pid != 0) {
                // Parent, wait for the child
                while ((pid = wait(&status)) > 0);    
                if(WIFEXITED(status)){
                    std::cout << "EXITED NORMALLY:)" << std::endl;
                }
                if(WIFSIGNALED(status)){
                    int signumber = WTERMSIG(status);
                    std::cout << "EXITED DUE TO SIGNAL " << signumber << std::endl;
                }
                _exit(0);
            }
        }

		// Read in input file into memory
		std::string inputFile = argv[1];
        std::ifstream file(inputFile, std::ios::binary);
        file.seekg (0, file.end);
        size_t buf_size = file.tellg();
        file.seekg (0, file.beg);
        uint8_t* buffer = (uint8_t*)malloc(sizeof(char) * buf_size);
        file.read((char*)buffer, buf_size);
        fuzz_one_input(buffer, buf_size);
}