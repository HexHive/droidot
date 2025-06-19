import os, tempfile
import subprocess

BASE = os.path.dirname(__file__)

target_APK = os.path.join(BASE, "..", "target_APK")


def get_edge_ids(coverage_file):
    return set(k.split(":")[0] for k in open(coverage_file, "r").read().split("\n") if k.split(":")[0] != "")

def merge_coverage_harnesses(app, harnesses):
    # merge coverage maps 
    cov_maps = os.path.join(target_APK, app, "fuzzing_output", "cov_maps")
    if not os.path.exists(cov_maps):
        return []
    cov_map = set()
    for harness in harnesses:
        covmap_path = os.path.join(cov_maps,f'{harness}_covmap')
        if not os.path.exists(covmap_path):
            continue
        cov_map = cov_map.union(get_edge_ids(covmap_path))
    return list(cov_map)


if __name__ == "__main__":
    app = 'vidma.screenrecorder.videorecorder.videoeditor.pro'
    harnesses = list(os.listdir(f"../target_APK/{app}/fuzzing_output/"))
    print(merge_coverage_harnesses(app, harnesses))
