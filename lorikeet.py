#!/usr/bin/env python

#standard libary
import re
import os
import sys
import json

def main(argv):
    if len(argv) < 2:
        print("Please provide path to source code")
        print("Syntax: ./sast <path_to_file>")
        sys.exit(0)
    if len(argv) > 2:
        print("Too many arguments")
        print("Syntax: ./sast <path_to_file>")
        sys.exit(0)
    source_files = get_source(argv[1])
    static_buffs = get_static_buffs(source_files)
    for _row in static_buffs:
        _row["constants"] = should_be_const(_row.get("Source File"))
        
def get_source(the_path):
    """This function gets all the source code files for the source 
    code location
    Args:
        the_path (string): the path to your source code directory
    Return:
        all_files (list): a list of all the source code files from the dirctory 
            provided
    """
    dir_list = os.listdir(the_path)
    all_files = list()

    for _file in dir_list:
        cur_path = os.path.join(the_path,_file)
        if os.path.isdir(cur_path):
            all_files = all_files + get_source(cur_path)
        else:
            if ".git" in cur_path:
                continue
            elif ".c" or ".h" in cur_path:
                all_files.append(cur_path)
            else:
                continue

    return all_files

def get_static_buffs(files):
    """Gets static buffers from source code files
    Args:
        files (list): list of source code files to check 
        for static buffers
    Returns:
        vuln_list (list): A list of dicts with files and static buffers in files
    """
    vuln_list = list()
    for file in files:
        _curr_list = list()        
        with open(file, 'r') as code: 
            for _row in code:
                _curr = _row.strip()
                defines_pointer = re.match(r'\w+\s+\*\w+\[\w+\]\;', _curr)
                defines_array = re.match(r'\w+\s+\w+\[\w+\]\;', _curr)
                if defines_pointer or defines_array:
                   _curr_list.append(_curr)
        if _curr_list:
            vuln = intrest_obj(file, _curr_list)
            vuln_list.append(vuln)
    return vuln_list

def should_be_const(file):
    """Gets all variables that should be declared as const 
    Args:
        file (string) : current file that is being checked for varibales that should 
                    be constant.
    Returns:
        const (list): list of all variables that should be constant within this source
                    code file
    """
    mutations = list()
    variables = list()
    const = list()
    with open(file, 'r') as code:
        var_list = list()
        for _row in code:
            _curr = _row.strip()
            var = re.match(r'\w+\s+\w+\s+\=\s+\w+\;', _curr)
            char_var = re.match(r'\w+\s+\*\w+(?:\s+)\=(?:\s+)\"\w+\"\;', _curr)
            if var or char_var:
                var_list.append(_curr)
    
    for _var in var_list:

        _var_change = str(_var.split()[1]) + " ="
        with open(file, 'r') as code:
             for _row in code:
                _curr = _row.strip()
                if _var.split()[1] in _curr:
                    variables.append(_curr)

    for _row in variables:
        dec = re.match(r'[a-z]+\s+[a-z]+\s+\=\s+', _row)
        dec_two = re.match(r'[a-z]+\s+\*[a-z]+\s+\=\s+', _row)
        if dec or dec_two:
            pass
        else:
            mutations.append(_row)

    for _row in mutations:
        mutation = _row.split(" ")[0]
        for _row in variables:
            _row_tmp = _row.split(" ")
            if mutation in _row_tmp:
                pass
            else:
                if _row not in const:
                    const.append(_row)

    return const

def intrest_obj(source_file, buffs):
    """creates an object for potential vulns in
    source files
    Args:
        source_file (string): file name and location for source code
        buffs (list): list of static buffers 
    Returns:
        obj (dict): dict object with all static buffs within a
            given source file 
    """
    obj = {
    "Source File": source_file,
    "Static Buffers" : buffs
        }
    return obj


if __name__ == '__main__':
    main(sys.argv)