import os

BASE = os.path.dirname(__file__)

FUZZING_DIRECTORY = "/data/local/tmp/fuzzing/"
COMPILE_DIRECTORY = "/data/local/tmp/compile"
TARGET_APK_PATH = os.path.join(BASE, "..", ".." , "target_APK")
FUZZ_DB = os.path.join(BASE, "..", "..", "fuzz.db")
