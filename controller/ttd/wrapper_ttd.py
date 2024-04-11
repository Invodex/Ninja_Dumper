import subprocess
import re
import os

ttd_path = None
out_path = None

def run_ttd(cdb_commands):
    global cdb_path,dump_path
    env = os.environ.copy()
    # Incluindo o argumento fixo antes de -c
    cmd = [cdb_path ,"-z",dump_path,"-c", cdb_commands]
    #cmd = [command_path, dump_path, cdb_commands]
    #try:
    # Executando o cdb.exe com o argumento fixo e os comandos especificados
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', shell=False, env=env)
        
    # Retornando o output
    return {"success": True, "output": result.stdout, "error": result.stderr}
    #except subprocess.CalledProcessError as e:
        # Retornando o erro se o processo falhar
    #    return {"success": False, "output": e.stdout, "error": e.stderr}