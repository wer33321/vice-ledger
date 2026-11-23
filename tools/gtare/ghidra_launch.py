"""Running Ghidra scripts. All Ghidra interaction goes through the scripts in ghidra_scripts/.

Ghidra up to 11.x runs .py scripts with Jython inside analyzeHeadless. Newer
releases ship without Jython and use PyGhidra instead (pip install pyghidra);
the runner is chosen automatically from the install folder.
"""
import os
import subprocess
import sys

from .config import ConfigError

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ghidra_scripts")
PYGHIDRA_RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pyghidra_runner.py")


def find_headless(install):
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    path = os.path.join(install, "support", name)
    if not os.path.isfile(path):
        raise ConfigError("Could not find %s. 'ghidra_install' must be the folder that contains "
                          "'ghidraRun' (e.g. C:\\ghidra_11.3_PUBLIC)." % path)
    return path


def uses_pyghidra(install):
    return not os.path.isdir(os.path.join(install, "Ghidra", "Features", "Jython"))


def run_script(cfg, script, args, read_only):
    """Run a script headlessly against the configured program. Returns the process exit code."""
    headless = find_headless(cfg["ghidra_install"])
    print("Running Ghidra headless (close the project in the Ghidra GUI first)...")
    if uses_pyghidra(cfg["ghidra_install"]):
        try:
            import pyghidra  # noqa: F401
        except ImportError:
            raise ConfigError("This Ghidra has no Jython, so scripts run through PyGhidra. Install it with:\n"
                              "  pip install pyghidra\n(a wheel is also bundled in "
                              "<ghidra>\\Ghidra\\Features\\PyGhidra\\pypkg\\dist)")
        cmd = [sys.executable, PYGHIDRA_RUNNER, cfg["ghidra_install"], cfg["executable"], cfg["ghidra_project_dir"],
               cfg["ghidra_project_name"], cfg["ghidra_program"], os.path.join(SCRIPTS_DIR, script)] + list(args)
    else:
        cmd = [headless, cfg["ghidra_project_dir"], cfg["ghidra_project_name"],
               "-process", cfg["ghidra_program"], "-noanalysis",
               "-scriptPath", SCRIPTS_DIR, "-postScript", script] + list(args)
        if read_only:
            cmd.append("-readOnly")
    try:
        return subprocess.call(cmd)
    except OSError as exc:
        raise ConfigError("Failed to start Ghidra: %s" % exc)
