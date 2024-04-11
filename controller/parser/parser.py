import json

def va_info(memory_data):
    """
    !bug need to view the mem and base address, the addrs not match. parsing error :c !

    Function responsible for parsing information from the virtual allocated memory and printing it to the console.

    ARG1|Memory_data: JSON to parse

    RET: None

    """

    print("─" * 40 + "\n")
    for item in memory_data:
        area_name = item.split(':')[0].strip('{')
        mem_info_start = item.find('{mem:') + 5
        mem_info_end = item.find('}', mem_info_start)
        mem_info = item[mem_info_start:mem_info_end].split(',')
        
        base = mem_info[0].split(':')[1]
        end = mem_info[1].split(':')[1]
        size = mem_info[2].split(':')[1]
        
        perm_info_start = item.find('{Protect:') + 1
        perm_info_end = item.find('}', perm_info_start)
        perm_info = item[perm_info_start:perm_info_end].replace('"', '').split(',')
        
        protect = perm_info[0].split(':')[1]
        alloc_protect = perm_info[1].split(':')[1]

        print(f"Area: {area_name}")
        print(f"Base: {base}, End: {end}, Size: {size}")
        print(f"Permissions: Protect = {protect}, Allocation Protect = {alloc_protect}")
        print("─" * 40 + "\n")

def stack_trace(stack_trace):
    """

    Function responsible for parsing stack trace information in the console.

    ARG1|stack_trace: List to parse

    RET: None
    
    """

    stack_list = [eval(item) for item in stack_trace]
    
    print("Stack Trace Visualization:")
    print("Start ->", end="")
    for i, item in enumerate(stack_list, 1):
        for function, info in item.items():
            print(f"\n  |")
            print(f"  +-- {i}. Function: {function}")
            print(f"      |")
            print(f"      +-- Child-SP: {info['Child-SP']}")
            print(f"      +-- RetAddr: {info['RetAddr']}")
            if i < len(stack_list):
                print("      |")
                print("      v", end="")
    print("\nEnd of Stack Trace")

def registers(registers):
    """
    
    Function responsible for parsing register information in the console.

    ARG1|registers: List of registers to parse

    RET: None

    """

    general_purpose, segment_flags = registers


    max_width = max(len(reg) for reg in general_purpose + segment_flags) + 4
    
    top_border = "┌" + "─" * max_width + "┐"
    bottom_border = "└" + "─" * max_width + "┘"

    def print_registers(reg_list):
        for reg in reg_list:
            padding = max_width - len(reg) - 1
            print(f"│ {reg}{' ' * padding}│")

    print(top_border)
    print_registers(general_purpose)
    print_registers(segment_flags)
    print(bottom_border)

def modules(modules):
    """
    Function responsible for parsing module information in the console.

    ARG1|modules: List of modules to parse

    RET: None

    """

    print("Loaded Modules Visualization:\n")
    print("┌─" + "─" * 38 + "┐")
    for i, module in enumerate(modules):
        if i % 2 == 0:
            print(f"│ {module:<18} ", end="")
        else:
            print(f"{module:<18} │")
    if len(modules) % 2 != 0:
        print(" " * 18 + "│")
    print("└─" + "─" * 38 + "┘")

def exported_functions(info_list):
    """
    
    Function responsible for parsing information of functions exported by a module in the console.

    ARG1|info_list: List of functions exported by a module

    RET: None

    """
    cleaned_info = [item.replace('`', '') for item in info_list]
    
    max_width = max(len(item) for item in cleaned_info) + 4
    
    top_border = "┌" + "─" * max_width + "┐"
    bottom_border = "└" + "─" * max_width + "┘"

    print(top_border)
    
    str_end = ""
    for item in cleaned_info:
        str_end +=  item + '\r\n'
    return str_end

def va_extract(input_list, debug_name): #extract base,size and name from va
    """
    Function responsible for extracting base_addr, size, and name from a virtual address.

    ARG1|input_list: List of virtual addresses (va).
    ARG2|debug_name: Name to extract from the list.

    RET: name, base_addr, end_addr, size

    """

    for item in input_list:
        data = json.loads(item)
        
        if debug_name in data:
            debug_data = data[debug_name]['mem']
            return debug_name, debug_data['base'], debug_data['end'],debug_data['size']

def sum_debug_sizes(debug_list):
    """

    Function responsible for summing the size of a list of virtual addresses. Used in the process of allocating memory for Binary Ninja.

    ARG1|debug_list: List of virtual addresses (va).

    RET: Total sum

    """

    total_size = 0
    for debug_str in debug_list:
        debug_info = json.loads(debug_str)
        for debug_key in debug_info:
            size_str = debug_info[debug_key]["mem"]["size"]
            size_int = int(size_str, 16)
            total_size += size_int
    return total_size