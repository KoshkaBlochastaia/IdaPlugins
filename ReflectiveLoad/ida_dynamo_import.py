import idc
import json

#need to change it to read neme from command line in the future...
hash_file = "C:/Users/vakhapkina/Documents/py-scipts/hash-table.json"

def find_function_arg(addr):
  i = 0
  while True:
    addr = idc.prev_head(addr)
    i += 1
    # ecx reg number == 1
    if print_insn_mnem(addr) == "mov" and "ecx" == print_operand(addr, 0): 
      # print("We found it at 0x%x" % (int(get_operand_value(addr, 1)) & 0xFFFFFFFF))
      return (int(get_operand_value(addr, 1)) & 0xFFFFFFFF)

    if i == 10:
      break
  return None

#it sounds like magic, but i make a hash-table) 
def from_hash_to_str(api_hash, hash_table):
  if str(hex(api_hash)) in hash_table.keys():
    return hash_table[str(hex(api_hash))]
  return ""

def find_function_arg_2(addr):
  i = 0
  while True:
    addr = idc.next_head(addr)
    i += 1
    # ecx reg number == 1
    if print_insn_mnem(addr) == "mov" and "rax" == print_operand(addr, 1): 
      print("We found API at 0x%x" % (int(get_operand_value(addr, 0)) & 0xFFFFFFFF))
      return get_operand_value(addr, 0)

    if i == 10:
      break
  return None


api_loader_adddr = 0x61F8A3C0

print("-------START-------")
hash_table = {}
with open(hash_file, "r") as fn:
  hash_table = json.load(fn)

for addr in XrefsTo(api_loader_adddr, flags=0):
  print(hex(addr.frm))
  api_hash = find_function_arg(addr.frm)
  if api_hash == None:
    continue
  api_name = from_hash_to_str(api_hash, hash_table)
  print("Hash {} --> {} API".format(str(hex(api_hash)), api_name))
  if api_name == "":
    continue
  api_addr = find_function_arg_2(addr.frm)  
  if api_addr != None:
    set_name(api_addr, api_name, SN_PUBLIC) 

#                                        mov     rdx, rax
# .text:0000000061F838A2                 mov     ecx, 0EC0E4E8Eh
# .text:0000000061F838A7                 call    reflective_load_api
# .text:0000000061F838AC                 mov     rdx, r12
# .text:0000000061F838AF                 mov     ecx, 16B3FE72h
# .text:0000000061F838B4                 mov     cs:LoadLibraryA, rax
# .text:0000000061F838BB                 call    reflective_load_api
# .text:0000000061F838C0                 mov     rdx, r12
# .text:0000000061F838C3                 mov     ecx, 88A9223Ch
# .text:0000000061F838C8                 mov     cs:CreateProcessA, rax
#   ---------------------------...----------------------------
# .text:0000000061F84057                 mov     ecx, 7CB922F6h
# .text:0000000061F8405C                 mov     cs:qword_61FB1150, rax
# .text:0000000061F84063                 call    reflective_load_api
# .text:0000000061F84068                 mov     cs:qword_61FB15A8, rax


