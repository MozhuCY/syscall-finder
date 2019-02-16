__author__="mozhucy"

import sys
import re
from pwn import *

# rax,rdi,rsi,rdx,r10,r8,r9
# [rax,ArgsCount]
syscall_num = {}
func_list = {}

def printerr():
    print "use python syscall.py 'fun(reg,reg,reg,reg,...)' x64/x86 or syscall.py -f funname"

def init_syscall_num_dic():
    f = open(".x64_syscall.dat","r")
    line = f.readline()
    while line:
        ss = line.strip().split(",")
        syscall_num[ss[1]] = [ss[0],7 - ss.count("")]
        line = f.readline()

def out_bytecode(fun,arch):
    func_name = fun.split("(")[0]
    arg = re.findall("\((.{,})\)",fun)
    if len(arg) > 1:
        printerr()
        exit(0)
    args = arg[0].split(",")
    print args
    if arch == "x64":
        context.arch = "amd64"
        reglist = ["rax","rdi","rsi","rdx","r10","r8","r9"]
    elif arch == "x32":
        context.arch = "i386"
        reglist = []
    dat = syscall_num[func_name]
    _asm = "xor %s,%s\n"%(reglist[0],reglist[0])
    _asm += "mov %s,%d\n"%(reglist[0],int(dat[0]))
    
    for i in range(dat[1]):
        _asm += "mov %s,%s\n"%(reglist[i + 1],args[i])

    _asm += "syscall\n"
    print "ASM: \n%s"%_asm
    HEX = asm(_asm).encode("hex")
    print "HEX: %s\n"%(HEX)
    print "disasm: \n%s"%(disasm(HEX.decode("hex")))


#################
#get func args #
################


def init_func_find_dic():
    f = open(".x64_syscall.dat","r")
    line = f.readline()
    while line:
        ss = line.strip().split(",")
        func_list[ss[1]] = ss[2:]
        line = f.readline()

def find_syscall(funcname):
    try:
        count = 7 - func_list[funcname].count("")
        out = funcname + "("
        for i in range(count):
            out += func_list[funcname][i]
            out += ","
        out = out[:-1]
        out += ")"
        print out
    except:
        print "not found!"

if __name__=="__main__":
    if len(sys.argv) != 3:
        printerr()
        exit(0)
    
    l = sys.argv
    # print l
    fun = l[1]
    arch = l[2]
    if fun == "-f":
        init_func_find_dic()
        find_syscall(arch)
    else:
        init_syscall_num_dic()
        out_bytecode(fun,arch)
        
    