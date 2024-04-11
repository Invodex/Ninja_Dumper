import binaryninja
from ..view import view as vi
from ..writer import Write_Operations as wop
from ..windbg import wrapper_dump as wrapper
from ..parser import parser as parse
from ..mem_map import Sections_Operations as ope
import os

def open_dump():
    """
    
    Function responsible for opening the dump file in the wrapper.

    RET: Pipe to the wrapper process

    """

    path_dump = vi.get_file_path()
    appdata_path = os.getenv('APPDATA')
    appdata_path += r"\Binary Ninja\plugins\Ninja_Dumper"
    dbg_path = wrapper.get_paths_bin(appdata_path)
    dump_path = path_dump
    return wrapper.SubprocessController([dbg_path,'-z',dump_path]),path_dump

def List_all_modules(pipe_controller):
    """
    Function responsible for listing all modules from the dump file in the console.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|bv: Current BV

    RET: None

    """

    parse.modules(wrapper.filter_module_names_to_list_name(wrapper.list_modules(pipe_controller)))

def get_exports_from_module(pipe_controller,bv): # work need
    vi.showResultWindow(parse.exported_functions(wrapper.list_apis_from_name(pipe_controller,vi.get_user_input(bv))))

def get_regs(pipe_controller):
    """
    Function responsible for listing all registers from the dump file in the console.

    ARG1|pipe_controller: Pipe to the wrapper process

    RET: None

    """

    parse.registers(wrapper.get_all_regs(pipe_controller))

def stack_trace(pipe_controller):
    """
    Function responsible for listing the entire stack trace from the dump file in the console.

    ARG1|pipe_controller: Pipe to the wrapper process

    RET: None

    """

    parse.stack_trace(wrapper.get_stack(pipe_controller))

def list_va(pipe_controller):
    """
    Function responsible for listing all allocated memory from the dump file in the console.

    ARG1|pipe_controller: Pipe to the wrapper process

    RET: None

    """

    parse.va_info(wrapper.list_va(pipe_controller))

def export_mem_heap_to_file(pipe_controller,path_dump,bv):
    """
    
    Function responsible for dumping a memory area allocated by the dumped process to disk.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|path_dump: Path to the folder for file creation
    ARG3|bv: Current BV

    RET: None

    """

    result = parse.va_extract(wrapper.list_va(pipe_controller),vi.get_user_input(bv))
    wrapper.export_structured_module(pipe_controller,result[1],result[2],path_dump,result[0],'.mem')

def load_mem_to_bv(pipe_controller,path_dump,bv):
    """
    Function responsible for loading a memory area allocated by the dumped process into Binary Ninja.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|path_dump: Path to the folder for the file to be loaded
    ARG3|bv: Current BV

    RET: None

    """

    result = parse.va_extract(wrapper.list_va(pipe_controller),vi.get_user_input(bv))
    va_path = wrapper.export_structured_module(pipe_controller,result[1],result[2],path_dump,result[0],'.mem')
    ope.create_and_write_section(bv, result[0], result[1],result[2], result[3],wop.open_file_to_bytearray(va_path))
    ope.create_section_name_to_segment(bv,result[0],result[1],result[3])
    os.remove(va_path)

def load_main_module(pipe_controller,path_dump,bv): 
    """
    Function responsible for loading the main module from the dump into Binary Ninja.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|path_dump: Path to the folder for the file to be loaded
    ARG3|bv: Current BV

    RET: None

    """

    result = wrapper.get_main_mod(pipe_controller)
    main_mod_path = wrapper.export_structured_module(pipe_controller,result[1][0],result[1][1],path_dump,result[0],'_load_mapped.mapped')
    main_mod_fixed_bytes = wop.pe_dump_fix(main_mod_path)
    path_main_mod_on_disk = wop.write_bytearray_to_file(main_mod_fixed_bytes,path_dump,result[0]+'_load.exe')
    wop.insert_zeros_to_meet_size_raw(path_main_mod_on_disk,parse.sum_debug_sizes(wrapper.list_va(pipe_controller)))
    wop.write_hex_to_bview(bv,wop.open_file_to_bytearray(path_main_mod_on_disk))
    os.remove(main_mod_path)
    os.remove(path_main_mod_on_disk)

def expor_main_mod(pipe_controller,path_dump,bv):
    """

    Function responsible for dumping the main module from the dump file to disk.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|path_dump: Path to the folder for the file to be created
    ARG3|bv: Current BV

    RET: None

    """

    result = wrapper.get_main_mod(pipe_controller)
    main_mod_path = wrapper.export_structured_module(pipe_controller,result[1][0],result[1][1],path_dump,result[0],'_main.mapped')
    main_mod_fixed_bytes = wop.pe_dump_fix(main_mod_path)
    wop.write_bytearray_to_file(main_mod_fixed_bytes,path_dump,result[0]+'.exe')
    os.remove(main_mod_path)

def expor_selected_mod(pipe_controller,path_dump,bv):
    """

    Function responsible for dumping a selected module from the dump file to disk.

    ARG1|pipe_controller: Pipe to the wrapper process
    ARG2|path_dump: Path to the folder for the file to be created
    ARG3|bv: Current BV

    RET: None

    """
    result = wrapper.filter_modules_from_list(wrapper.list_modules(pipe_controller),vi.get_user_input(bv),"address")
    module_path = wrapper.export_structured_module(pipe_controller,result[0],result[1],path_dump,result[2],'_maped.dll')
    module_fixed_bytes = wop.pe_dump_fix(module_path)
    wop.write_bytearray_to_file(module_fixed_bytes,path_dump,result[2]+'.dll')#write fixed module to disk
    os.remove(module_path)

def Checksum():
    """
    need work :c

    """
    lala = "lala"