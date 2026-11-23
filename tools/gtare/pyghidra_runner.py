"""Helper process: run a Ghidra script against an existing project program via PyGhidra.

usage: pyghidra_runner.py <ghidra_install> <exe> <project_dir> <project_name> <program> <script> [script args...]
"""
import os
import sys

import pyghidra

install, exe, proj_dir, proj_name, program, script = sys.argv[1:7]
os.environ["GHIDRA_INSTALL_DIR"] = install
pyghidra.run_script(exe, script, project_location=proj_dir, project_name=proj_name, script_args=sys.argv[7:],
                    analyze=False, program_name=program, nested_project_location=False, install_dir=install)
