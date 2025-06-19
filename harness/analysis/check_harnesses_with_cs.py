import os
import sys
import lib.utils
import lib.callsequence
import re


target_APK_path = sys.argv[1]
CS_analysis_path = sys.argv[2]

for analysis_output in os.listdir(CS_analysis_path):
    app = analysis_output[:3:-4]
    print(app)
    fInfos = lib.utils.parse_sig_lib_offsets(open(os.path.join(target_APK_path, app, "signatures_libraries_offsets.txt")).read())
    with open(os.path.join(CS_analysis_path, analysis_output), "r") as f:
        fname2phenomcs = lib.callsequence.parse_phenom_callsequence(f.read(), fInfos)
