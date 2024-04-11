from binaryninja import *
import os
import pefile
import mmap

def write_bytearray_to_file(raw_data,path_dmp,name):
    """
    Function responsible for receiving a bytearray and writing its content to a file.

    ARG1|raw_data: bytearray
    ARG2|path_dmp: Path for writing to disk.
    ARG3|name: Name of the file

    RET: Path to the written file.

    """

    dir_path = os.path.dirname(path_dmp)
    with open(dir_path + '/' + name, "wb") as file:
        file.write(raw_data)
    return  (dir_path + '/' + name )

def write_hex_to_bview(bv,data):
    """
    Function responsible for writing a bytearray to the BV of Binary Ninja.

    ARG1|bv: Current BV
    ARG2|data: ByteArray

    RET: None

    """

    data_bytearray = data
    bv.write(0,data_bytearray)

def pe_dump_fix(file_path):
    """
    Function responsible for fixing the content dumped from memory to disk.

    ARG1|file_path: Path to the broken file

    RET: Bytearray with the fixed binary

    """

    with open(file_path, "r+b") as pe_file:
        mm = mmap.mmap(pe_file.fileno(), 0)
        
        pe = pefile.PE(data=mm[:1024], fast_load=True)
        
        if pe.is_exe():
            if pe.FILE_HEADER.Machine == 0x014c:
                pe.relocate_image(0x400000)
            elif pe.FILE_HEADER.Machine == 0x8664:
                pe.relocate_image(0x140000000)
            else:
                arch = "Desconhecida"
        if pe.is_dll():
            if pe.FILE_HEADER.Machine == 0x014c:
                pe.relocate_image(0x10000000)
            elif pe.FILE_HEADER.Machine == 0x8664:
                pe.relocate_image(0x180000000)
            else:
                arch = "Desconhecida"

        for i, section in enumerate(pe.sections):
            section.PointerToRawData = section.VirtualAddress

        for i, section in enumerate(pe.sections):
            if i < len(pe.sections) - 1:
                next_section = pe.sections[i + 1]
                diff = next_section.PointerToRawData - section.PointerToRawData
                section.SizeOfRawData = diff
            else:
                if section.Name.rstrip(b'\x00') == b'.reloc':
                    section.SizeOfRawData = 0
                else:
                    pass
            section.VirtualSize = section.SizeOfRawData
        mm[:len(pe.write())] = pe.write()
            
        mm.flush()
        mm.close()

        with open(file_path, "rb") as file:
            content = file.read()
        return bytearray(content)

def open_file_to_bytearray(file_path):
    """

    Function responsible for opening a file into a bytearray.

    ARG1|file_path: Path to the file

    RET: Bytearray of the binary

    """

    with open(file_path, "rb") as file:
        content = file.read()
    return bytearray(content)

def insert_zeros_to_meet_size_raw(file_path, size_raw, distance_from_end=0x50):
    """
    Function responsible for allocating memory for Binary Ninja, enabling the allocation of all data extracted from the virtual memory allocated by the dumped process and loading it into Binary Ninja. This method was devised as a solution to load more data into the database. When attempting to load all memory data into the database, Binary Ninja would not allow creating segments or writing more than the size of the opened file. Therefore, this function was created to perform the "allocation" :)

    ARG1|file_path: Path to the file
    ARG2|size_raw: Amount of memory to "allocate" in the file
    ARG3|distance_from_end: Space between the last written byte and the "allocated" memory

    RET: None
    """

    try:
        size_raw += 100
        with open(file_path, 'rb') as file:
            content = file.read()
        
        insert_point = len(content) - distance_from_end
        
        if insert_point < 0:
            raise ValueError("oh no :c")

        bytes_to_insert = b'\x00' * size_raw

        modified_content = content[:insert_point] + bytes_to_insert + content[insert_point:insert_point + distance_from_end]

        with open(file_path, 'wb') as file:
            file.write(modified_content)

        print(f"Inserted {size_raw} bytes 0x00 into the file '{file_path}', maintaining a distance of {hex(distance_from_end)} from the end.")

    except Exception as e:
        print(f"Error modifying the file: {e}")