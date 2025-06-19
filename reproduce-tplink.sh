#!/bin/bash

./start_single_emu.py emulator-5580

python3 harness/harness_generator.py -jo_ok -cs_ph -cs_io -cs_ph_min_len 1 -ct_argval -fuzz --target com.tplink.skylight

rm -rf target_APK/com.tplink.skylight/fuzzing_output/Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@arg-cs-io@1-0/*

python3 fuzzing/fuzz.py --target com.tplink.skylight --target_function Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@arg-cs-io@1-0 --device emulator-5580 -t 120

python3 fuzzing/triage.py -c --target com.tplink.skylight --target_function Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@arg-cs-io@1-0 -r --device emulator-5580

cat target_APK/com.tplink.skylight/fuzzing_output/Java_com_tplink_skylight_common_jni_MP4Encoder_packVideo@arg-cs-io@1-0/reproduced_crashes/folder2backtraces.txt
