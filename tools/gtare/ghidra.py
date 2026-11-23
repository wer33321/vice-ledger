"""Running Ghidra scripts. All Ghidra interaction goes through the scripts in ghidra_scripts/."""
import os
import subprocess

from .config import ConfigError

SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "ghidra_scripts")


def find_headless(install):
    name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    path = os.path.join(install, "support", name)
    if not os.path.isfile(path):
        raise ConfigError("Could not find %s. 'ghidra_install' must be the folder that contains "
                          "'ghidraRun' (e.g. C:\\ghidra_11.3_PUBLIC)." % path)
    return path


def run_script(cfg, script, args, read_only):
    """Run a script headlessly against the configured program. Returns the process exit code."""
    headless = find_headless(cfg["ghidra_install"])
    cmd = [headless, cfg["ghidra_project_dir"], cfg["ghidra_project_name"],
           "-process", cfg["ghidra_program"], "-noanalysis",
           "-scriptPath", SCRIPTS_DIR, "-postScript", script] + list(args)
    if read_only:
        cmd.append("-readOnly")
    print("Running Ghidra headless (close the project in the Ghidra GUI first)...")
    try:
        return subprocess.call(cmd)
    except OSError as exc:
        raise ConfigError("Failed to start Ghidra: %s" % exc)
