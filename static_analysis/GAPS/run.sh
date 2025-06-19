#!/usr/bin/env bash

if [ $# -ne 1 ]; then
        echo "Usage: $0 <apps_path>"
        exit 1
fi

app_path=$1
files=$(ls $app_path|grep .apk$)

for file in $files; do
	echo $file
	timeout -s SIGALRM 30m python3 -m gaps -i $app_path/$file -o ./io 
	echo "done"
	rm -rf /tmp/*.cache
done
