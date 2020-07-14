# Compute Windows Exception runtime for 64b.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

def_UNW_FLAG_EHANDLER  = 1
def_UNW_FLAG_UHANDLER  = 2
def_UNW_FLAG_CHAININFO = 4

def parse_UNWIND_INFO(start_rt, end_rt, unwind_rt):
    flags = getByte(toAddr(unwind_rt)) >> 3
    header_size = getByte(toAddr(unwind_rt+1))
    countOfCodes = getByte(toAddr(unwind_rt+2))*2
    size_header = countOfCodes+4
    if (size_header & 0x3) != 0:
        size_header += 2
    if (flags & def_UNW_FLAG_EHANDLER) == def_UNW_FLAG_EHANDLER:
        exception_handler = getInt(toAddr(unwind_rt+size_header))
        count_exception_handlers = getInt(toAddr(unwind_rt+size_header+4))
        createMemoryReference(createDWord(toAddr(unwind_rt+size_header)), toAddr(exception_handler+imagebase), ghidra.program.model.symbol.RefType.DATA)
        size_header += 8
        # print count_exception_handlers
        if count_exception_handlers < 0x10:
            for cexpId in range(count_exception_handlers):
                start_func = getInt(toAddr(unwind_rt+size_header+(cexpId*0x10)))
                createMemoryReference(createDWord(toAddr(unwind_rt+size_header+(cexpId*0x10))), toAddr(start_func+imagebase), ghidra.program.model.symbol.RefType.DATA)
                end_func = getInt(toAddr(unwind_rt+size_header+(cexpId*0x10)+4))
                createMemoryReference(createDWord(toAddr(unwind_rt+size_header+(cexpId*0x10)+4)), toAddr(end_func+imagebase), ghidra.program.model.symbol.RefType.DATA)
                exp_func = getInt(toAddr(unwind_rt+size_header+(cexpId*0x10)+8))
                createMemoryReference(createDWord(toAddr(unwind_rt+size_header+(cexpId*0x10)+8)), toAddr(exp_func+imagebase), ghidra.program.model.symbol.RefType.DATA)
                jmp_func = getInt(toAddr(unwind_rt+size_header+(cexpId*0x10)+0xc))
                if jmp_func != 0:
                    createMemoryReference(createDWord(toAddr(unwind_rt+size_header+(cexpId*0x10)+0xc)), toAddr(jmp_func+imagebase), ghidra.program.model.symbol.RefType.DATA)
                print "  Handler %x" % (exp_func+imagebase)
    

mem = currentProgram.getMemory()
imagebase = currentProgram.treeManager.getDefaultRootModule().getFirstAddress().offset
for block in mem.getBlocks():
    if block.getName() == ".pdata":
        # print dir(block)
        runtime_function_address = block.getStart()
        index = 0
        unwind_rt =1
        while unwind_rt != 0:
            start_rt = getInt(toAddr(runtime_function_address.offset+(index*0xc)))
            end_rt = getInt(toAddr(runtime_function_address.offset+(index*0xc)+4))
            unwind_rt = getInt(toAddr(runtime_function_address.offset+(index*0xc)+8))
            if unwind_rt != 0:
                print "%x: %x <-> %x : %x" % (runtime_function_address.offset+(index*0xc), start_rt+imagebase, end_rt+imagebase, unwind_rt+imagebase)
                dword_start_rt = createDWord(toAddr(runtime_function_address.offset+(index*0xc)))
                dword_end_rt = createDWord(toAddr(runtime_function_address.offset+(index*0xc)+4))
                dword_unwind_rt = createDWord(toAddr(runtime_function_address.offset+(index*0xc)+8))
                createMemoryReference(dword_start_rt, toAddr(start_rt+imagebase), ghidra.program.model.symbol.RefType.DATA)
                # setPlateComment(toAddr(start_rt+imagebase),"Exception start address",True)
                # setPlateComment(toAddr(dword_end_rt+imagebase),"Exception end address",True)
                # setPlateComment(toAddr(unwind_rt+imagebase),"Exception Unwind infos",True)
                createMemoryReference(dword_end_rt, toAddr(end_rt+imagebase), ghidra.program.model.symbol.RefType.DATA)
                createMemoryReference(dword_unwind_rt, toAddr(unwind_rt+imagebase), ghidra.program.model.symbol.RefType.DATA)
                # break
                parse_UNWIND_INFO(start_rt+imagebase, end_rt+imagebase, unwind_rt+imagebase)
            index += 1
