import json 
import sys 
import os
import re

boring_args = ['ByteBuffer', 'byte[]', 'String', 'string', 'int', 'long', 'byte', 'short', 'float', 'double', 'boolean', 'void', 'char']
boring_apis = ['GetByteArrayElements', 'ReleaseByteArrayElements', 'GetStringUTFChars', 'ReleaseStringUTFChars', 'GetStringLength',
               'ReleaseStringChars', 'GetStringChars', 'GetStringUTFLength', 'GetDirectBufferAddress', 'GetDirectBufferCapacity', 'GetByteArrayRegion']

inp_folder = sys.argv[1]

libs_analyzed = set()
apks_analyzed = set()
funcs_analyzed = set()
funcs_with_detected_jni = set()
jni_api_with_params = {}
jni_api_without_params =  {}
overall_jni_usages_found = 0
jni_api_with_interesting_params = {}
jni_api_with_resolved_params = {}

for analyzed in os.listdir(inp_folder):
    if not analyzed.endswith(".json"):
        continue
    apk = analyzed[:analyzed.find("_")]
    library = analyzed[analyzed.find("_")+1:].split(".jnifuncs.json")[0]
    library = library[:library.find(".so")+3]
    print(apk,library)
    data = json.load(open(os.path.join(inp_folder, analyzed)))
    apks_analyzed.add(apk)
    libs_analyzed.add(library)
    for func in data:
        funcs_analyzed.add(func["java_function"]["java_name"])
        if len(func["jni_api_calls"])  == 0:
            continue
        if func["java_function"]["java_name"] in funcs_with_detected_jni:
            continue
        funcs_with_detected_jni.add(func["java_function"]["java_name"])
        print(func["java_function"]["java_name"])
        for jni_call in func["jni_api_calls"]:
            if len(jni_call)  == 0:
                continue
            print(jni_call)
            try: 
                jni_call = jni_call[0]
            except:
                pass
            param_found = False
            overall_jni_usages_found += 1
            for p in jni_call["parameters"]:
                match = re.match(r"param_([0-9]+)", p)
                if match:
                    param_found = True
                    ind = int(match[1])-3 # -1 is the input object, starting from 0, java args
                    print(ind, p, func["java_function"]["args"])
                    if ind == -1:
                        arg_interesting = True
                    if len(func["java_function"]["args"]) <= ind:
                        # TODO: fix overloading, just a hack for now
                        continue
                    elif func["java_function"]["args"][ind] not in boring_args:
                        arg_interesting = True
                    else:
                        arg_interesting = False
                    if arg_interesting and jni_call["api"] not in boring_apis:
                        if jni_call["api"] not in jni_api_with_interesting_params:
                            jni_api_with_interesting_params[jni_call["api"]] = 0
                        jni_api_with_interesting_params[jni_call["api"]] += 1
                    elif arg_interesting and jni_call["api"] in boring_apis:   
                        if jni_call["api"] not in jni_api_with_resolved_params:
                            jni_api_with_resolved_params[jni_call["api"]] = 0
                        jni_api_with_resolved_params[jni_call["api"]] += 1
                    if jni_call["api"] in boring_apis:
                        continue
                    if jni_call["api"] not in jni_api_with_params:
                        jni_api_with_params[jni_call["api"]] = 0
                    jni_api_with_params[jni_call["api"]] += 1
                    break
            if not param_found:
                if jni_call["api"] not in jni_api_without_params:
                    jni_api_without_params[jni_call["api"]] = 0
                jni_api_without_params[jni_call["api"]] += 1

print("overall jni usages: ", overall_jni_usages_found)

print("==================APIs with interesting param usage==================")
s = 0
for api, cnt in jni_api_with_interesting_params.items():
    print(api, cnt)
    s += cnt
print("overall interesting jni api usages with interesting param: ", s)

print("==================APIs with resolved param usage==================")
s = 0
for api, cnt in jni_api_with_resolved_params.items():
    print(api, cnt)
    s += cnt
print("overall resolved jni api usages with param: ", s)

print("==================APIs found with param usage==================")
s = 0
for api, cnt in jni_api_with_params.items():
    print(api, jni_api_with_params[api])
    s += cnt
print("overall jni api usages with param: ", s)


print("==================APIs found without param usage==================")
s = 0
for api, cnt in jni_api_without_params.items():
    print(api, cnt)
    s += cnt
print("overall jni api usages without param: ", s)

                    




