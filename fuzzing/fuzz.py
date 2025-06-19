import sys
import time
import os
import argparse
import json
import logging
import shutil
import time
BASE_PATH = os.path.dirname(__file__)
sys.path.append(os.path.join(BASE_PATH, '..'))
sys.path.append(os.path.join(BASE_PATH, 'lib'))
import adb
import testing
import interface


def fuzz(app, harness, device, time_tofuzz):
    interface.wait_for_device(device)
    out_dir = interface.setup_fuzz(app, harness, device)
    interface.start_fuzz(app, harness, out_dir, device, cmplog=1, check_started=1)
    time.sleep(time_tofuzz)
    interface.stop_fuzz(device)
    interface.fetch_fuzz_one(app, harness, out_dir, device)
    print("[FUZZ]FUZZING OUTPUT DIRECTORY: ", out_dir)


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=f'fuzz specific function')
    parser.add_argument("--target", type=str, required=True, help="The appname in target_APK")
    parser.add_argument("--target_function", type=str, required=True, help="The harness name of the native function")
    parser.add_argument("--device", type=str, required=True, help="specify a specific device on which to test")
    parser.add_argument("-t", "--time", default=False, type=int, help="time to fuzz")

    args = parser.parse_args()    

    fuzz(args.target, args.target_function, args.device.encode(), args.time)
