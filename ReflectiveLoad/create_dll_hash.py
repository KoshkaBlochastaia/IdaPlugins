# this is my file for dumping function hashes in json
# all your need - to change hash function)
# ВРРРРРРРРРР №1 

import re
import sys
import json
import argparse
import subprocess


# I reg dumpbin.exe in system PATH, so i can execute it in any folder
command = "dumpbin.exe /exports C:\\windows\\system32\\{} /out:{}"
# this command make strange trace of dll export in your file

# ror for 4 bytes 
def ror( dword, bits ):
  return (( dword >> bits | dword << ( 32 - bits ) ) & 0xFFFFFFFF)

# calculate ror hash, ror13 in defolt
def ror_hash(function, bits=13):
    function_hash = 0
    for c in str( function):
      function_hash  = ror( function_hash, bits ) 
      function_hash  = (function_hash + ord(c)) 
    return function_hash

# i use it to execute powershell commands
def run(self, cmd):
    completed = subprocess.run(["powershell", "-Command", cmd], capture_output=True)
    return completed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Parse sandbox logs as you want')
    parser.add_argument('-O','--out', dest="outfile", help='name of file ti store hashes-api json')
    parser.add_argument('-A','--append', dest="append", help='append hash export results at your file')
    parser.add_argument('library', help='name of DLL file to hash it exports')
    args = parser.parse_args()
    module = args.library
    print("I execute command: ", command.format(module, module+".txt"))
    hash_table = {} 
    out_file = module + ".txt"
    if args.outfile != None:
        out_file = args.out_file
    run_rez = run(1, command.format(module, out_file))
    if run_rez.returncode != 0:
        print("An error occured: %s", run_rez.stderr)
    else:
        print("Command executed successfully!")
    
    print("-------------------------")
    print("Start calculating hashes from {} library".format(module))
    hash_num = 0
    with open(out_file, 'r') as fn:
        for line in fn:
            api_str = re.search(r'[0-9a-fA-F]\s+0[0-9a-fA-F]+\s+(.+)', line)
            if api_str == None or len(api_str.group(1)) < 3:
                api_str = re.search(r'[0-9a-fA-F]          ([^\s@]+)', line)
            if api_str != None:
                fun_name = api_str.group(1)
                # if fun_name == "1":
                #     print("What a PROBLEM?!!!!!!!!! ", api_str.group())
                fun_hash = ror_hash(fun_name)
                hash_table[str(hex(fun_hash))] = fun_name
                hash_num += 1
    print("Calculate {} hashes".format(hash_num))
    res_file_name = module+".json"
    if args.append != None:
        print("Append hashes to {} file".format(args.append))
        fn = open(args.append, 'r')
        prev_hash_table = json.loads(fn.read())
        # i dont now, why two * used there.... but it make union of two dictionares!
        hash_table = dict(prev_hash_table, **hash_table)
        res_file_name = args.append
    with open(res_file_name, "w") as json_fn:
        json.dump(hash_table, json_fn)
        print("Successfully save result in {} file".format(res_file_name))

            
            




