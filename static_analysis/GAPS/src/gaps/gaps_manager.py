import os
import subprocess
import logging
from collections import defaultdict
from androguard.misc import AnalyzeDex, AnalyzeAPK
from androguard.misc import Session
from os import listdir
import json
import csv
import signal
import time
import gc

from . import dalvik_disassembler
from . import method_utils
from . import path_generation

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

###############################################################################
# CODE
###############################################################################


class GapsManagerException(Exception):
    pass


class GapsManager:
    """Graph-Automated Path Synthesizer"""

    def __init__(
        self,
        dalvik_path: str,
        outdir: str,
        tot_alt_paths: int = 5000,
        path_len: int = 200,
        resume: bool = False,
        per_dex_analysis: bool = False,
        inter_procedural: bool = False,
    ):
        self.start_time = time.time()
        signal.signal(signal.SIGALRM, self.handler)
        if not os.path.exists(dalvik_path):
            raise (GapsManagerException("dalvik_path does not exist"))

        self.dalvik_path = dalvik_path
        self.tot_alt_paths = tot_alt_paths
        self.path_len = path_len
        self.resume = resume
        self.per_dex_analysis = per_dex_analysis
        self.inter_procedural = inter_procedural
        self.outdir = outdir

        self.starting_points = set()
        self.session = Session()
        self._reset()
        self._setup()

    def _reset(self):
        self.session.reset()
        self.dalvik = None
        self.dx = None
        self.search_list = {}
        self.requested = set()
        self.addr_to_instr = dict()
        self.instr_cfg = defaultdict(set)
        self.instructions_to_address = defaultdict(set)
        self.native_addrs = set()
        self.instr_to_parent_method = dict()

    def _collect_garbage(self):
        LOG.info("[+] COLLECTING GARBAGE")

        del self.dalvik
        del self.dx
        del self.search_list
        del self.requested
        del self.addr_to_instr
        del self.instr_cfg
        del self.instructions_to_address
        del self.native_addrs
        del self.instr_to_parent_method

        gc.collect()

    def _setup(self):
        self.file_name = os.path.splitext(os.path.basename(self.dalvik_path))[
            0
        ]
        self.json_output = {}
        self.parent_method = ""
        self.stats_row = [self.file_name, 0, 0, 0, 0, 0]
        self.tmp_path = os.path.join("/tmp", self.file_name + ".cache")

        self._init_stats()

        partial_result_file_path = os.path.join(
            self.outdir, f"{self.file_name}-instr.json"
        )
        self.partial_results = None
        if self.resume and os.path.exists(partial_result_file_path):
            with open(partial_result_file_path, "r") as partial_result_file:
                self.partial_results = json.load(partial_result_file)

        ext = os.path.splitext(self.dalvik_path)[1]
        if ext == ".apk":
            dalvik_disassembler.run_apktool(self)
            if self.per_dex_analysis:
                self.analyze_multi_dex()
            else:
                self.analyze_apk()
        elif ext == ".dex":
            self.analyze_dex()
            self._run_dex_analysis()
        else:
            raise (GapsManagerException("input file is not .dex or .apk"))

        self._write_output_json()
        self._save_stats()
        LOG.info("--- %s seconds ---" % (self.stats_row[1]))

    def analyze_dex(self):
        dalvik_disassembler.run_baksmali(self)
        self.dump_native_target_methods()

    def _run_dex_analysis(self):
        self.dalvik, _, self.dx = AnalyzeDex(
            self.dalvik_path, session=self.session
        )
        dalvik_disassembler.disassemble(self)
        self.start_path_finding()

    def analyze_apk(self):
        self.dump_native_target_methods()
        self.dalvik, _, self.dx = AnalyzeAPK(self.dalvik_path)
        dalvik_disassembler.disassemble(self)
        self.start_path_finding()

    def analyze_multi_dex(self):
        original_tmp_path = self.tmp_path
        dex_files = []
        for app_file in listdir(original_tmp_path):
            ext = os.path.splitext(app_file)[1]
            if (
                os.path.isfile(os.path.join(original_tmp_path, app_file))
                and ext == ".dex"
            ):
                self.dalvik_path = os.path.join(original_tmp_path, app_file)
                self.tmp_path = os.path.join(
                    original_tmp_path, app_file + ".cache"
                )
                self.analyze_dex()
                dex_files.append(app_file)

        for dex_file in dex_files:
            self.dalvik_path = os.path.join(original_tmp_path, dex_file)
            self.tmp_path = os.path.join(
                original_tmp_path, dex_file + ".cache"
            )
            self._run_dex_analysis()
            self._collect_garbage()
            self._reset()

    def dump_native_target_methods(self):
        grep = subprocess.Popen(
            f'grep -r "^\\.method.* native " {self.tmp_path}',
            shell=True,
            stdout=subprocess.PIPE,
        )
        output_grep = grep.communicate()[0].decode("utf-8").split("\n")
        for class_method in output_grep:
            if class_method.strip():
                path_class_name = class_method.split(".smali")[0]
                path_class_name = path_class_name.split(self.tmp_path)[1][1:]
                if path_class_name.startswith("smali"):
                    path_class_name = path_class_name.split("/")[1:]
                    path_class_name = "/".join(path_class_name)
                class_name = "L" + path_class_name
                target_method = class_method.split()[-1]
                key = class_name + ";->" + target_method
                self.starting_points.add(key)
        LOG.debug(f"[+] FOUND {len(self.starting_points)} NATIVE METHODS\n")

    def _write_output_json(self):
        if self.resume:
            partial_result_file_path = os.path.join(
                self.outdir, f"{self.file_name}-instr.json"
            )
            with open(partial_result_file_path, "r") as partial_result_file:
                partial_results = json.load(partial_result_file)

            partial_results.update(self.json_output)

            self._check_allpaths_constraints(partial_results)

            with open(partial_result_file_path, "w") as partial_result_file:
                json.dump(partial_results, partial_result_file)
        else:
            json_file_path = os.path.join(
                self.outdir, f"{self.file_name}-instr.json"
            )
            self._check_allpaths_constraints(self.json_output)
            json_object = json.dumps(self.json_output, indent=4)
            with open(json_file_path, "w") as json_file:
                json_file.write(json_object)

    def _check_allpaths_constraints(self, json_content):
        for jni_key in json_content:
            params_visited = {}
            for constraint_dicts in json_content[jni_key]:
                for param in constraint_dicts:
                    if param.startswith("param"):
                        if param not in params_visited:
                            params_visited[param] = True
                            for cd in json_content[jni_key]:
                                if param not in cd:
                                    params_visited[param] = False
                                    break
                        if param in params_visited:
                            constraint_dicts[param]["constraint"][
                                "allpaths"
                            ] = params_visited[param]

    def handler(self, signum, frame):
        self._write_output_json()
        self._save_stats()
        raise (GapsManagerException("GAPS exiting, sigalarm received"))

    def _init_stats(self):
        stats_csv_path = os.path.join(self.outdir, "stats.csv")
        if not os.path.exists(stats_csv_path):
            with open(stats_csv_path, "w") as stats_file:
                stats_writer = csv.writer(
                    stats_file,
                    delimiter=",",
                    quotechar='"',
                    quoting=csv.QUOTE_MINIMAL,
                )
                stats_writer.writerow(
                    [
                        "APP",
                        "TIME",
                        "TOT. NATIVE CALLS",
                        "NATIVE CALLS COMPLETED",
                        "UNIQUE CONSTRAINTS COLLECTED",
                        "HARNESSES",
                    ]
                )

    def _save_stats(self):
        stats_csv_path = os.path.join(self.outdir, "stats.csv")
        with open(stats_csv_path, "a") as stats_file:
            stats_writer = csv.writer(
                stats_file,
                delimiter=",",
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL,
            )

            self.stats_row[1] = time.time() - self.start_time

            self.stats_row[5] = len(self.json_output)

            stats_writer.writerow(self.stats_row)

    def start_path_finding(self):
        self.stats_row[2] += len(self.native_addrs)
        for starting_point in self.native_addrs:
            _current_instr = self.addr_to_instr[starting_point]
            if self.resume and self.partial_results:
                jni_mangled_call = path_generation._get_jni_mangled_name(
                    _current_instr, self
                )
                if jni_mangled_call in self.partial_results:
                    continue
            LOG.debug(f"[+] LOOKING FOR {_current_instr}")
            (
                _search_class_name,
                _search_method_name,
            ) = method_utils.get_class_and_method(_current_instr, True)
            partial_paths = path_generation.find_path_smali_native(
                _search_method_name,
                self,
                target_class=_search_class_name,
                starting_points=[starting_point],
            )
            # path_generation.print_paths(partial_paths)
            if partial_paths:
                LOG.debug(f"[+] PATHS: {len(partial_paths)}")
                path_generation.generate_instructions(partial_paths, self)
            LOG.debug("-" * 100)
            self.stats_row[3] += 1
