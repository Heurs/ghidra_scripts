# Backtrace a selected register.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

colorize = False

from java.awt import Color

service = state.getTool().getService(ghidra.app.plugin.core.colorizer.ColorizingService)
if service is None:
     print "Can't find ColorizingService service"
if currentSelection is not None:
     service.setBackgroundColor(currentSelection, Color(255, 200, 200))
elif currentAddress is not None:
     service.setBackgroundColor(currentAddress, currentAddress, Color(255, 200, 200))
else:
     print "No selection or current address to color"

addresses_to_color = ghidra.program.model.address.AddressSet()


registers_to_trace = ['RAX','RBX','RCX','RDX','RSI','RDI','RBP','R8','R9','R10','R11','R12','R13','R14','R15']

def get_write_register(instruction):
    # instruction.getPcode()[1].getOutput().isRegister()
    objects = [a for a in instruction.getResultObjects()]
    top_objects = []
    for cobj in objects:
        if type(cobj) == ghidra.program.model.lang.Register:
            while cobj != None and cobj.getParentRegister() != None:
                cobj = cregister.getParentRegister()
            if str(cobj) in registers_to_trace:
                top_objects.append(cobj)
    return list(set(top_objects))

def get_read_register(instruction):
    objects = [a for a in instruction.getInputObjects()]
    top_objects = []
    for cobj in objects:
        if type(cobj) == ghidra.program.model.lang.Register:
            while cobj != None and cobj.getParentRegister() != None:
                cobj = cregister.getParentRegister()
            if str(cobj) in registers_to_trace:
                top_objects.append(cobj)
    return list(set(top_objects))

if 'operandRepresentation' in dir(currentLocation):
    str_reg = currentLocation.operandRepresentation
    cregister = currentProgram.listing.getInstructionAt(currentAddress).getRegister(str_reg)
    while cregister.getParentRegister() != None:
        cregister = cregister.getParentRegister()
    traced_regs = [cregister]
    local_function = getFunctionContaining(currentAddress)
    # print currentProgram.listing.getInstructionBefore(currentAddress)
    cinstr = currentProgram.listing.getInstructionAt(currentAddress)
    caddress = cinstr.getAddress()
    block_to_backtrace = []
    done_instr_addr = []
    while cinstr != None and len(traced_regs) > 0 and getFunctionContaining(caddress) == local_function and not(caddress in done_instr_addr):
        done_instr_addr.append(caddress)
        reg_list_write = get_write_register(cinstr)
        reg_list_read = get_read_register(cinstr)
        # print cinstr
        to_del_reg = []
        for c_traced_reg in traced_regs:
            if c_traced_reg in reg_list_write:
                to_del_reg.append(c_traced_reg)
        if len(to_del_reg) > 0:
            # print to_del_reg
            addresses_to_color.add(caddress)
            print "%s %s" % (caddress, cinstr)
        
        # print reg_list_read
        if len(to_del_reg) > 0:
            for creg in reg_list_read:
                if not(creg in traced_regs):
                    traced_regs.append(creg)
        
        if cinstr.mnemonicString in ['MOV','LEA','XOR']:
            for cdel in to_del_reg:
                traced_regs.remove(cdel)
        
        prev_list = cinstr.getReferenceIteratorTo()
        if prev_list != None:
            for cprev in prev_list:
                if cprev != None:
                    # print cprev
                    block_to_backtrace.append([currentProgram.listing.getInstructionAt(cprev.getFromAddress()), cprev.getFromAddress(),traced_regs])
        cinstr = currentProgram.listing.getInstructionBefore(caddress)
        caddress = cinstr.getAddress()
        if cinstr.mnemonicString in ['JMP','RET'] or getFunctionContaining(caddress) != local_function:
            if len(block_to_backtrace) > 0:
                cinstr, caddress, traced_regs = block_to_backtrace.pop()
    
    if colorize == True:
        setBackgroundColor(addresses_to_color, Color(255, 200, 200))
    
    print "End of BackTracing"
else:
    print "No register selected"
