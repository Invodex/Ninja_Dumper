import subprocess
import os
import re

# Global paths for the CDB tool and the dump file it operates on
cdb_path = None
dump_path = None

def run_ttd(cdb_commands):
    """
    Executes the CDB (Windows Debugger) command-line tool with specified commands on a dump file.

    This function configures the environment for the CDB tool, constructs the command with predefined
    paths, and executes it while capturing the output. It handles errors internally and returns
    a dictionary indicating success status, command output, and any errors encountered.

    Parameters:
        cdb_commands (str): Commands to be executed by the CDB tool.

    Returns:
        dict: A dictionary with keys 'success', 'output', and 'error', detailing the execution results.
    """
    env = os.environ.copy()
    cmd = [cdb_path, "-z", dump_path, "-c", cdb_commands]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', shell=False, env=env)
    
    return {"success": True, "output": result.stdout, "error": result.stderr}
