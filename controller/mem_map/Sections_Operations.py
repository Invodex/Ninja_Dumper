from binaryninja import *

def create_section_name_to_segment(bv,section_name,base_address,size):
    """
    Function responsible for creating a section for the created segment.

    ARG1|bv: Current BV
    ARG2|section_name: Name of the section to be created
    ARG3|base_address: Start address
    ARG4|size: Size of the segment

    RET: None

    """

    bv.add_user_section(section_name, int(base_address,16), int(size,16))

def create_and_write_section(bv, section_name, base_address,end_address, size,fill_data):
    """
    Function responsible for creating and writing to a segment in the Binary Ninja BV.

    ARG1|bv: Current BV
    ARG2|section_name: Name of the segment to be created
    ARG3|base_address: Start address
    ARG4|end_address: End address
    ARG5|size: Size of the segment
    ARG6|fill_data: Data to write

    RET: None

    """

    max_data_offset = 0
    for segment in bv.segments:
        current_end = segment.data_offset + segment.data_length
        if current_end > max_data_offset:
            max_data_offset = current_end

    new_segment_start = bv.segments[-1].end
    new_data_offset = max_data_offset + 100

    bv.add_user_segment(int(base_address,16), int(size,16), new_data_offset, int(size,16), 0)
    if not bv.write(int(base_address,16), fill_data):
        print(f"Oh no :c error on '{section_name}'.")
        return 1
    
    print(f"Section '{section_name}' Added and filled with data.")