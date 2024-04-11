import subprocess
import threading
import queue
import re
import os
import sys

cdb_path = None
dump_path = None
PADD_STRING_START = "NinjaDumpNinj@Dump:)"

class SubprocessController:
    def __init__(self, command):
        startupinfo = None
        if sys.platform == 'win32':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
        self.command = command
        print(command)
        self.output_queue = queue.Queue()
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,encoding='utf-8', shell=False,startupinfo=startupinfo,env = os.environ.copy())
        self.thread = threading.Thread(target=self.read_output)
        self.thread.daemon = True
        self.thread.start()

    def read_output(self):
        while True:
            line = self.process.stdout.readline()
            if not line:
                break
            self.output_queue.put(line)

    def send_command(self, command):
        self.output_queue.queue.clear()
        full_command = '{}\r\n.echo {}\r\n'.format(command, PADD_STRING_START)
        self.process.stdin.write(full_command)
        self.process.stdin.flush()

        output_lines = []
        while True:
            line = self.output_queue.get()
            if PADD_STRING_START in line.strip():
                break
            output_lines.append(line)
        
        return ''.join(output_lines)

    def close(self):
        self.process.terminate()

def get_paths_bin(path):
    """
    Function responsible for receiving the path to the plugin folder and returning the path to the WinDbg binary. This function will be refactored in the future to use the binary from Binary Ninja itself.

    ARG1|path to the plugin folder

    RET: Path to the cdb.

    """

    path_exe = os.path.join(path,"controller","windbg", "bin", "cdb.exe")
    return path_exe

def parse_modules(module_parse):
    """
    Function responsible for parsing the raw list of modules and returning a list with all the information of the modules.

    ARG1|module_parse: List of modules to parse.

    RET: List of all parsed and organized modules.

    """

    pattern = r"([0-9a-f`]+)\s+([0-9a-f`]+)\s+([^\s]+)\s+\((deferred|pdb symbols)(?:\s*([^)]+))?\)"
    matches = re.findall(pattern, module_parse)

    module_names = []
    for start, end, module_name, symbol_status, pdb_path in matches:
        start = start.replace("`", "")
        end = end.replace("`", "")
        symbol_info = symbol_status
        if pdb_path:
            symbol_info += " " + pdb_path.strip()
        module_names.append({module_name:{"start": start, "end": end, "symbol": symbol_info}})

    return module_names

def list_modules(inst_class):
    """
    Function responsible for listing all the modules of the dumped process.

    ARG1|inst_class: Class containing the open pipe to the cdb process.

    RET: List with all the modules of the dumped process.

    """

    cdb_commands = 'lm'
    result = inst_class.send_command(cdb_commands)
    
    parse = result
    pattern = r"start\s+end\s+module name\s+([\s\S]+?)(?=NatVis script unloaded|quit:|\Z)"
    matched = re.search(pattern, parse)
    result = "start             end                 module name\n" + matched.group(1).strip() if matched else "No matching data found."
    return parse_modules(result)


def get_info_addr(inst_class,addr):
    """
    Function responsible for retrieving addresses and filtering all information about the specified address in the parameters.

    ARG1|inst_class: Class containing the open pipe to the cdb process.
    ARG2|addr: Target address for information gathering.

    RET: JSON with all information about that memory address.

    """

    cdb_commands = ""
    
    for item in addr[:-1]:
        cdb_commands += "!address " + item + ";"
    
    cdb_commands += "!address " + addr[-1]
    result = inst_class.send_command(cdb_commands)
    blocks = result.split("Usage:")[1:]
    
    pattern = re.compile(r"Base Address:\s+([^\n]+)\nEnd Address:\s+([^\n]+)\nRegion Size:\s+([^\n]+)\n.*?Protect:\s+([^\n]+)\n.*?Allocation Protect:\s+([^\n]+)", re.DOTALL)
    
    debug_infos = []
    
    for index, block in enumerate(blocks, start=1):
        match = pattern.search(block)
        if match:
            base_address, end_address, region_size, protect, allocation_protect = match.groups()
            
            base_address = base_address.replace("`", "")
            end_address = end_address.replace("`", "")
            
            region_size = region_size.split()[0].replace("`", "")
            
            protect = protect.split()[-1]  
            allocation_protect = allocation_protect.split()[-1]  
            
            debug_info = f"{{\"debug{index}\":{{\"mem\":{{\"base\":\"{base_address}\",\"end\":\"{end_address}\",\"size\":\"{region_size}\"}},\"perm\":{{\"Protect\":\"{protect}\",\"Allocation_Protect\":\"{allocation_protect}\"}}}}}}"
            debug_infos.append(debug_info)
    
    return debug_infos

def parse_enderecos_inicio(inst_class,va_list):
    """

    Function responsible for parsing and extracting all memory addresses allocated by the dumped process. Used in the function: "list_va".

    ARG1|inst_class: Class containing the open pipe to the cdb process.
    ARG2|va_list: Raw list of memory allocated by the dump.

    RET: Parsed list of memory allocated by the dumped process.

    """

    global cdb_path,dump_path
    lines = va_list.split('\n')
    
    addrs_init = []
    list_addr = []

    for line in lines:
        if line.strip().startswith('Segment at'):
            addr = line.split()[2]
            addrs_init.append(addr)
    return get_info_addr(inst_class,addrs_init)

def list_va(inst_class):
    """
    Function responsible for listing all the memory allocated by the dumped process and returning a list with information related to the memory area.

    ARG1|inst_class: Class containing the open pipe to the cdb process.

    RET: List with all active allocated memory of the dumped process.

    """

    cdb_commands = '!heap -a'
    result = inst_class.send_command(cdb_commands)
    return parse_enderecos_inicio(inst_class,result)
    

def get_stack(inst_class):
    """
    Function responsible for capturing the stack trace of the dumped program and returning a list with the flow of called functions and information about the functions' return.

    ARG1|inst_class: Class containing the open pipe to the cdb process.

    RET: List with the stack trace of the dumped program's execution.

    """

    cdb_commands = 'k'
    result = inst_class.send_command(cdb_commands)
    lines = result.strip().splitlines()[1:]

    formatted_calls_corrected = []

    for line in reversed(lines):
        parts = line.replace("`", "").split()
        if len(parts) < 3:
            continue
        child_sp = parts[0]
        ret_addr = parts[1]
        call_site = " ".join(parts[2:])

        formatted_call = f'{{"{call_site}":{{"Child-SP":"{child_sp}","RetAddr":"{ret_addr}"}}}}'
        formatted_calls_corrected.append(formatted_call)

    return formatted_calls_corrected

def get_all_regs(inst_class):
    """
    Function responsible for retrieving and returning a list with all general-purpose registers and selectors.

    ARG1|inst_class: Class containing the open pipe to the cdb process.

    RET: List of general-purpose registers and selectors.
    """

    cdb_commands = 'r'
    result = inst_class.send_command(cdb_commands)

    lines = result.splitlines()
    register_data = " ".join(lines).split()

    gen_registers = []
    selector_registers = []

    selector_registers_complete = False

    for item in register_data:
        if item == "0:000>" or selector_registers_complete:
            continue
        if item.startswith(("cs=", "ss=", "ds=", "es=", "fs=", "gs=", "efl=")):
            selector_registers.append(item)
            if item.startswith("efl="):
                selector_registers_complete = True
        elif not selector_registers_complete:
            gen_registers.append(item)

    gen_registers_filtered = [reg for reg in gen_registers if "=" in reg and not reg.startswith(('iopl', 'nv', 'up', 'ei', 'pl', 'zr', 'na', 'po', 'nc'))]

    rip_entry = next((reg for reg in gen_registers_filtered if 'rip=' in reg), None)
    if rip_entry:
        gen_registers_filtered.remove(rip_entry)
        gen_registers_filtered.append(rip_entry)

    end_regs_output = [gen_registers_filtered, selector_registers]
    return end_regs_output


def filter_modules_from_list(module_list, module_name, info_to_get):
    """
    Function responsible for filtering a module from a list by name and filtering its address or symbol info.

    ARG1|module_list: Complete list of modules.
    ARG2|module_name: Name of the module.
    ARG3|info_to_get: symbol: Get symbol | address: Get Address.

    RET: Module name, address or symbol.

    """

    for modulo in module_list:
        if module_name in modulo:
            modulo_info = modulo[module_name]
            if info_to_get == "address":
                return modulo_info['start'], modulo_info['end'], module_name
            elif info_to_get == "symbol":
                return modulo_info['symbol']
            else:
                return "invalid type."
    return "Module not found."

def filter_module_names_to_list_name(module_list):
    """
    Function responsible for receiving a list of modules and filtering only the names of the modules.

    ARG1|module_list: Complete list of the modules.

    RET: List of module names.

    """

    names = [list(d.keys())[0] for d in module_list]
    return names

# dont use thissssss XDXDXDXD
def list_apis_from_list_module(): # dont use this, it will get all functions from all modules including modules defaults from MS.
    modules_names = filter_module_names_to_list_name(list_modules())
    cdb_commands = ''
    for name in modules_names:
        cdb_commands += 'x {}!*;'.format(name)
    cdb_commands += 'q'
    result = run_cdb_dmp(cdb_commands)
    return result["output"]

def list_apis_from_name(inst_class,module_name):
    """
    Function responsible for exporting all function exports from a specific module.

    ARG1|inst_class: Class containing the open pipe to the cdb process.
    ARG2|module_name: Name of the module from which the exports are to be extracted.

    RET: List of exported function names.

    """

    module_list = list_modules(inst_class)
    cdb_commands = 'x /2 {}!*'.format(module_name)
    result = inst_class.send_command(cdb_commands)
    lines = result.strip().split('\n')
    
    count = 0
    end = len(lines)
    for i, line in enumerate(lines):
        if line.startswith("0:000>'"):
            count = i + 1
        elif line.startswith(PADD_STRING_START):
            end = i
            break
    
    line_last = lines[count:end]
    
    func_names_list = [line.split()[1] for line in line_last]
    
    return func_names_list

def export_structured_module(inst_class,addr_base,addr_end,path,name,exte):
    """
    Function responsible for writing the memory dump content to disk. The written content will be mapped to the process's virtual memory.

    ARG1|inst_class: Class containing the open pipe to the cdb process.
    ARG2|addr_base: Base address for the memory area.
    ARG3|addr_end: End address for the memory area.
    ARG4|path: Path to the file where the content will be written.
    ARG5|name: Name of the written file.
    ARG6|ext: Extension of the written file.

    RET: Path to the written file.
    """

    size = int(addr_end,16) - int(addr_base,16)
    write_path = os.path.dirname(path) + '/' + name + exte

    cdb_commands = '.writemem {} 0x{} L?0x{}'.format(write_path,addr_base,size)
    try:
        result = inst_class.send_command(cdb_commands)
        return write_path
    except:
        print("error on writting module to file")
        return 1
    

def get_main_mod(inst_class):
    """
    Function responsible for identifying the executable responsible for creating the process: main module. The function traverses the Process Environment Block (PEB) to locate the process's image PATH.
    
    ARG1|inst_class: Class containing the open pipe to the cdb process.

    RET: returns the name of the main module.
    """

    result = inst_class.send_command('!peb')
    lines = result.splitlines()

    executable_name = ""

    for line in lines:
        if "ImageFile:" in line:
            full_path = line.split("ImageFile:")[1].strip()
            executable_name = full_path.split("\\")[-1]
            break
    main_mod_name = executable_name.rstrip('.exe\'')
    return main_mod_name,filter_modules_from_list(list_modules(inst_class), main_mod_name, "address")

def get_mod_version_info(inst_class,module_name):
    cdb_commands = 'lmvm {}'.format(module_name)
    result = inst_class.send_command(cdb_commands)

def checksum_mod(inst_class,module_name):
    cdb_commands = '!chkimg {}'.format(module_name)
    result = inst_class.send_command(cdb_commands)