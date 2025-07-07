#!/bin/bash
#set -eux

# there are 100 apps in the folder target_APK
# for a quick evaluation, we recommend doing 10 of them at first
# NO_OF_APPS=100
NO_OF_APPS=10
app_list=$(ls target_APK | head -n $NO_OF_APPS)

mkdir -p results/poirot_arg
mkdir -p results/poirot_cs
mkdir -p results/flowdroid
mkdir -p results/droidreach
mkdir -p results/jucify

rm -rf target_APK/*.txt
for f in target_APK/*; do cp -f "$f/base.apk" "$f/$(basename "$f").apk" 2>/dev/null || true; done
for f in target_APK/*; do cp -f "$f/$(basename "$f").apk" "$f/base.apk" 2>/dev/null || true; done

total_apps=$(ls target_APK | wc -l)

echo -e "\n > \x1b[31mrunning poirot argument analysis pass\x1b[0m"
printf '%s\n' $app_list | parallel -j 1 'timeout -k 0 1800 /usr/lib/jvm/java-21-openjdk-*/bin/java -jar FlowdroidSimple/FlowDroidAnalysis.jar ./target_APK/{} abcd 1>./results/poirot_arg/{}.out 2>./results/poirot_arg/{}.err; a=$?; if [[ $a == 124 || $a == 137 ]]; then echo timeout {} ; elif [[ $a != 0 ]]; then echo crash $a {}; else echo ok {}; fi' |& tee poirot_arg_out.txt
echo "checking poirot argument analysis results"
timeout=$(grep -c 'timeout ' poirot_arg_out.txt)
out_of_memory=$(grep -c 'OutOfMemory' poirot_arg_out.txt)
crashed=$(grep -c 'crash ' poirot_arg_out.txt)
completed=$(grep -c 'ok' poirot_arg_out.txt)
echo "timeout: $timeout"
echo "out of memory: $out_of_memory"
echo "crashed: $crashed"
echo "completed: $completed"

echo -e "\n > \x1b[31mrunning poirot call sequence pass\x1b[0m"
rm -f workspace/nativesAnalysis/*
printf '%s\n' $app_list | parallel -j 1 'cd workspace; timeout -k 0 1800 ./run_low_memory.sh -j ../target_APK/{}/{}.apk 1>../results/poirot_cs/{}.out 2>../results/poirot_cs/{}.err; a=$?; if [[ $a == 124 || $a == 137 ]]; then echo timeout {} ; elif [[ $a != 0 ]]; then echo crash $a {}; else echo ok {}; fi' |& tee poirot_cs_out.txt
pwd
echo checking poirot call sequence results
echo "empty result: $(find workspace/nativesAnalysis -iname *.json -size 2c | wc -l)"
echo "timeout: $(grep -c 'timeout ' poirot_cs_out.txt)"
echo "out of memory: $(grep -c 'OutOfMemory' poirot_cs_out.txt)"
echo "crashed: $(grep -c 'crash ' poirot_cs_out.txt)"
echo "completed: $(find workspace/nativesAnalysis -iname *.json -size +3c | wc -l)"
 
echo -e "\n > \x1b[31mrunning flowdroid\x1b[0m"
printf '%s\n' $app_list | parallel -j 1  'timeout -k 0 1800 java -Xmx8192m -jar FlowDroid/soot-infoflow-cmd-jar-with-dependencies.jar -p /opt/android-sdk/platforms -d -s ./sources.txt -a target_APK/{}/{}.apk 1>results/flowdroid/{}.out 2>results/flowdroid/{}.err; a=$?; if [[ $a == 124 || $a == 137 ]]; then echo timeout {} ; elif [[ $a != 0 ]]; then echo crash $a {}; else echo ok {}; fi' |& tee flowdroid_out.txt
echo "checking flowdroid results"
timeout=$(grep -c 'timeout ' flowdroid_out.txt)
out_of_memory=$(grep -R 'OutOfMemory' results/flowdroid -l | wc -l)
crashed=$(grep -c 'crash ' flowdroid_out.txt)
completed=$(grep -R 'Found' results/flowdroid -l | wc -l)
empty_result=$(($NO_OF_APPS - timeout - out_of_memory - crashed - completed))
echo "timeout: $timeout"
echo "out of memory: $out_of_memory"
echo "crashed: $crashed"
echo "completed: $completed"
echo "empty result: $empty_result"

echo -e "\n > \x1b[31mrunning droidreach\x1b[0m"
printf '%s\n' $app_list | parallel -j 1 'timeout -k 0 1800 python3 dreach_wrapper.py ./DroidReach/bin/dreach --full-analysis target_APK/{}/{}.apk 1>results/droidreach/{}.out 2>results/droidreach/{}.err; a=$?; if [[ $a == 124 || $a == 137 ]]; then echo timeout {} ; elif [[ $a != 0 ]]; then echo crash $a {}; else echo ok {}; fi' |& tee droidreach_out.txt
echo "checking droidreach results"
timeout=$(grep -c 'timeout' droidreach_out.txt)
out_of_memory=$(grep -R 'Wrapper: Memory limit' results/droidreach -l | wc -l)
completed=$(grep -c 'ok ' droidreach_out.txt)
exit_code_1=$(grep -R "finished with return code 1" -l | wc -l)
empty_result=$(for f in results/droidreach/*.out; do if [[ "$(cat $f | wc -l)" -eq 3 ]]; then echo $f; fi; done | wc -l)
crashed=$(((exit_code_1 - empty_result)))
echo "timeout: $timeout"
echo "out of memory: $out_of_memory"
echo "crashed: $crashed"
echo "completed: $completed"
echo "empty result: $empty_result"


echo -e "\n > \x1b[31mrunning jucify\x1b[0m"
printf '%s\n' $app_list | parallel -j 1 'cd JuCify/scripts; timeout -k 0 1800 bash main.sh -p /opt/android-sdk/platforms -f ../../target_APK/{}/{}.apk 1>../../results/jucify/{}.out 2>../../results/jucify/{}.err; a=$?; if [[ $a == 124 || $a == 137 ]]; then echo timeout {} ; elif [[ $a != 0 ]]; then echo crash $a {}; else echo ok {}; fi' |& tee jucify_out.txt
timeout=$(grep -c 'timeout' jucify_out.txt)
out_of_memory=$(grep -c 'OutOfMemory' jucify_out.txt)
completed=$(for f in results/jucify/*.out; do grep -Pzoq "Analysis elapsed time:" $f && echo $f; done | wc -l)
crashed=$(grep Exception -R results/jucify/ | wc -l)
empty_result=$(for f in results/jucify/*.out; do grep -Pzoq "nodes before Jucify: (\d.*)\n.*nodes after Jucify: \1" $f && echo $f; done | wc -l)
completed=$(((completed - empty_result)))
echo "timeout: $timeout"
echo "out of memory: $out_of_memory"
echo "crashed: $crashed"
echo "completed: $completed"
echo "empty result: $empty_result"


for f in target_APK/*; do cp -f $f/base.apk $f/$(basename $f).apk 2>/dev/null || true; done
