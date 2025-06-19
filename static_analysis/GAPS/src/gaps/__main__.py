import sys
import os
import argparse
import logging

from .gaps_manager import GapsManager

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

###############################################################################
# CODE
###############################################################################


def start_gaps(
    dalvik_path: str,
    out_dir: str,
    tot_alt_paths: str,
    path_len: str,
    resume: bool = False,
    per_dex_analysis: bool = False,
    inter_procedural: bool = False,
) -> int:
    if not tot_alt_paths:
        tot_alt_paths = 5000
    else:
        tot_alt_paths = int(tot_alt_paths)
    if not path_len:
        path_len = 200
    else:
        path_len = int(path_len)
    GapsManager(
        dalvik_path,
        out_dir,
        tot_alt_paths,
        path_len,
        resume,
        per_dex_analysis,
        inter_procedural,
    )

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", help="APK/DEX path file to disassemble", required=True
    )
    parser.add_argument(
        "-o", "--outdir", help="Output directory", required=True
    )
    parser.add_argument(
        "-tot_alt_paths",
        "--tot_alt_paths",
        help="Total numer of alternative paths",
    )
    parser.add_argument(
        "-path_len",
        "--path_len",
        help="Specify max len of the paths",
    )
    parser.add_argument(
        "-resume",
        "--resume_analysis",
        help="Total numer of alternative paths",
        action="store_true",
    )
    parser.add_argument(
        "-per_dex",
        "--per_dex_analysis",
        help="If an apk, analyze one dex at a time",
        action="store_true",
    )
    parser.add_argument(
        "-inter",
        "--inter_procedural",
        help="Perform inter-procedural searches to add new constraints",
        action="store_true",
    )
    args = parser.parse_args(sys.argv[1:])

    LOG.info(f"[+] LOADING {args.input}")
    LOG.info(f"[+] OUTPUT {args.outdir}")
    if args.tot_alt_paths:
        LOG.info(f"[+] TOT. ALTERNATIVE PATHS {args.tot_alt_paths}")
    if args.path_len:
        LOG.info(f"[+] MAX PATH LEN {args.path_len}")
    if args.resume_analysis:
        LOG.info("[+] RESUMING ANALYSIS")
    if args.per_dex_analysis:
        LOG.info("[+] ANALYZING ONE DEX AT A TIME")
    if args.inter_procedural:
        LOG.info("[+] INTERPROCEDURAL ANALYSIS")

    if not os.path.isdir(args.outdir):
        parser.print_help()
        sys.exit()

    start_gaps(
        args.input,
        args.outdir,
        args.tot_alt_paths,
        args.path_len,
        args.resume_analysis,
        args.per_dex_analysis,
        args.inter_procedural,
    )
