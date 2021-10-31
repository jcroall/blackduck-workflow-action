#!/usr/bin/env python

import argparse
import json
import sys
import os
import subprocess

detect_cmd = "/detect.sh"

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Run Black Duck Security Scan")
    parser.add_argument("--url", required=True, type=str, help="Black Duck Hub URL")
    parser.add_argument("--token", required=True, type=str, help="Black Duck Hub Token")
    parser.add_argument("--input", default="blackduck-output", required=True, type=str, help="Output directory from Black Duck Scan Action")
    parser.add_argument("--fixpr", type=str, help="Create a Fix PR, true or false")
    parser.add_argument("--upgrademajor", type=str, help="Offer upgrades to major versions, true or false")
    parser.add_argument("--comment", type=str, help="Generate a comment on pull request, true or false")
    parser.add_argument("--sarif", type=str, help="SARIF output file")

    args = parser.parse_args()

    url = args.url
    token = args.token
    if (url == None or token == None):
        print(f"ERROR: Must specify Black Duck Hub URL and API Token")
        sys.exit(1)
    input_dir = args.input
    fixpr = args.fixpr
    upgrademajor = args.upgrademajor
    comment = args.comment
    sarif = args.sarif

    os.environ["BLACKDUCK_TOKEN"] = token

    cmd_opts = f"--url=\"{url}\" --output_directory=\"{input_dir}\" --output \"{sarif}\" --debug 9 "
    if (fixpr == "true"):
        cmd_opts = cmd_opts + " --fixpr"
    if (upgrademajor == "true"):
        cmd_opts = cmd_opts + " --upgrademajor"
    if (comment == "true"):
        cmd_opts = cmd_opts + " --comment"

    os.system("pwd")
    os.system("find . -print")
    os.system("ls -lR")

    for k, v in sorted(os.environ.items()):
        print(k+':', v)

    print(f"EXEC: python3 /blackduck-rapid-scan-to-sarif-bdio.py {cmd_opts}")

    result = subprocess.Popen(f"python3 /blackduck-rapid-scan-to-sarif-bdio.py {cmd_opts}", shell=True)
    cmd_output = result.communicate()[0]
    return_code = result.returncode

    print(f"INFO: Done, return value {return_code}")

    sys.exit(return_code)
