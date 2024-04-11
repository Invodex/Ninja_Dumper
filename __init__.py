from binaryninja import *
from .controller.handler import handler as initial
from .controller import main as main

PluginCommand.register("Ninja Dump\\Load Dump", "Load Dump", main.Load_dump)
PluginCommand.register("Ninja Dump\\Load Main Module", "Load Main ProcMod", main.Load_Main_Module)

PluginCommand.register("Ninja Dump\\Info\\List Modules", "List All Modules Names", main.List_All_Modules)
PluginCommand.register("Ninja Dump\\Info\\Get Regs", "Get all regs", main.Show_Regs)
PluginCommand.register("Ninja Dump\\Info\\Stack Trace", "Get stack trace", main.Show_Stack_Trace)
PluginCommand.register("Ninja Dump\\Info\\Get exported func from module", "Get all exported func", main.Get_Exports_from_module) # need work

PluginCommand.register("Ninja Dump\\Dump\\Export Module", "Export Module", main.Export_Module_By_Name)
PluginCommand.register("Ninja Dump\\Dump\\Dump Main Mod", "Dump Mod" , main.Dump_main_mod)
PluginCommand.register("Ninja Dump\\Dump\\Dump Heap", "Dump Mod" ,main.Dump_mem_heap_to_file)

PluginCommand.register("Ninja Dump\\Heap\\List Heap", "Get heap from dump", main.List_All_Virtual_Address)
PluginCommand.register("Ninja Dump\\Heap\\Load Heap To BNinja", "Export Module", main.Load_heap_to_bv)