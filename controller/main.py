from .view import view as vi
from .writer import Write_Operations as wop
from .windbg import wrapper_dump as wrapper
from .handler import handler as hand

pipe_controller = None
path_dump = None

def Load_dump(bv):
    global pipe_controller,path_dump
    pipe_controller,path_dump = hand.open_dump()

def Load_Main_Module(bv):
    hand.load_main_module(pipe_controller,path_dump,bv)

def Export_Module_By_Name(bv):
    hand.expor_selected_mod(pipe_controller,path_dump,bv)

def List_All_Modules(bv):
    hand.List_all_modules(pipe_controller)

def Show_Regs(bv):
    hand.get_regs(pipe_controller)

def Show_Stack_Trace(bv):
    hand.stack_trace(pipe_controller)

def List_All_Virtual_Address(bv):
    hand.list_va(pipe_controller)

def Get_Exports_from_module(bv):
    hand.get_exports_from_module(pipe_controller,bv)

def Load_heap_to_bv(bv):
    hand.load_mem_to_bv(pipe_controller,path_dump,bv)

def Dump_main_mod(bv):
    hand.expor_main_mod(pipe_controller,path_dump,bv)

def Dump_mem_heap_to_file(bv):
    hand.export_mem_heap_to_file(pipe_controller,path_dump,bv)