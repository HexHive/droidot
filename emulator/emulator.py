import adb
import time
import subprocess
import threading


RED='\033[0;31m'                                                   
YELLOW='\033[0;33m'                                                                                                                          
GREEN='\033[0;32m'                                                                                                                           
NC='\033[0m'                                                                                                                                 
BLUE='\033[0;34m'         # Blue                                      
PURPLE='\033[0;35m'       # Purple                                                                                                           
CYAN='\033[0;36m'         # Cyan 


def start_emulators_threaded(nr):
    if nr == 0:
        return
    ts = []
    for i in range(0, nr):
        ts += [threading.Thread(target=start_emulator, args=[f'emulator-{5554+i*2}'])]
    list(map(lambda x: x.start(), ts))
    list(map(lambda x: x.join(), ts))
    while len(adb.get_device_ids()) < nr:
        print(f"Waiting to start emulators... currently online: {len(adb.get_device_ids())} out of {nr}")
        time.sleep(5)
    print(f"All {nr} are up!")

def device2ports(device_id):
    if isinstance(device_id, bytes):
        device_id = device_id.decode()
    # emulator-5554 -> ports 5554,5555
    p1 = int(device_id.split("-")[1])
    return p1, p1+1


def start_emulator(device_id):
    if isinstance(device_id, bytes):
        device_id = device_id.decode()
    init_devices = adb.get_device_ids()
    p1,p2 = device2ports(device_id)
    if device_id.encode() in init_devices:
        print(f"{PURPLE}[EMU]{NC} emulator already running")
        return device_id.encode()
    print(f"{PURPLE}[EMU]{NC} Starting android emulator")
    subprocess.Popen(f"docker exec -d mycontainer emulator @pixel -read-only -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -ports {p1},{p2}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    while True:
        out, err = adb.execute_privileged_command('getprop sys.boot_completed', device_id=device_id)
        if out == b'1\n':
            break
        time.sleep(5)
    time.sleep(10)
    subprocess.Popen(f'docker exec -it mycontainer bash -c "cd /mnt/emulator && bash emu_gdb.sh {device_id}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    new_devices = adb.get_device_ids()
    new_dev = set(new_devices) - set(init_devices)
    if len(new_dev) == 0:
        print(f"{RED}[EMU]{NC} Failed to start emulator")
        return None
    new_dev = list(new_dev)[0]
    print(f"{GREEN}[EMU]{NC} Emulator succesfully started: {new_dev}")
    return new_dev

def stop_emulator(device_id):
    subprocess.Popen(f"docker exec -d mycontainer adb -s {device_id} emu kill", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return
