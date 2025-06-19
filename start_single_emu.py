#!/bin/python3
import sys

from emulator.emulator import *
if len(sys.argv) >= 2:
    start_emulator(sys.argv[1])
else:
    start_emulator('emulator-5554')
