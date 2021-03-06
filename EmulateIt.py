# Emulate code from the current address.

# DISCLAIMER: This is a recreation of a Java Ghidra script for example
# use only. Please run the Java version in a production environment.

#@category Examples.Python

emuHelper = ghidra.app.emulator.EmulatorHelper(currentProgram)
# emuHelper.writeRegister("RAX", 0x20)
# emuHelper.writeMemoryValue(toAddr(0x000000000008C000), 4, 0x99AABBCC)
# emuHelper.writeMemory(toAddr(0x00000000000CF000), b'\x99\xAA\xBB\xCC')

if str(emuHelper.getLanguage()) == "x86/little/32/default":
    reg_filter = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "eflags"]
    reg_state = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "eflags"]
elif str(emuHelper.getLanguage()) == "x86/little/64/default":
    reg_filter = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RSP", "RBP", "rflags"]
    reg_state = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RSP", "RBP", "rflags"]
else:
    reg_filter = [a for a in currentProgram.getProgramContext().registers]
    reg_state = [a for a in currentProgram.getProgramContext().registers]

import random
cycles = random.randint(0,0xffffffffffffffff)

def do_rdtsc():
    emuHelper.writeRegister("EAX", cycles & 0xffffffff)
    emuHelper.writeRegister("EDX", cycles >> 32)

handled_instructions = {
    "RDTSC" : do_rdtsc,
}


# emuHelper.writeRegister("RBX", 0xf7fff8c000000000)
# emuHelper.writeRegister("RCX", 0xfffff8c000000000)
# emuHelper.writeRegister("RDX", 0xfffff8c100000000)
# emuHelper.writeRegister("RSP", 0xfffff8c200000000)

mainFunctionEntry = currentAddress
end_addr = -1

ceslection = currentSelection
if ceslection != None:
    min_addr = None
    for csel in ceslection.getAddressRanges():
        if min_addr == None:
            min_addr = csel.getMinAddress().getOffset()
        if min_addr > csel.getMaxAddress().getOffset():
            min_addr = csel.getMaxAddress().getOffset()
        if end_addr < csel.getMaxAddress().getOffset():
            end_addr = csel.getMaxAddress().getOffset()
    end_addr = toAddr(end_addr)
    mainFunctionEntry = toAddr(min_addr)
mainFuncLong = int("0x{}".format(mainFunctionEntry), 16)
emuHelper.writeRegister(emuHelper.getPCRegister(), mainFuncLong)

count_max = askInt("Number of instructions", "enter instructions count")
monitor = ghidra.util.task.ConsoleTaskMonitor()
count = 0
while monitor.isCancelled() is False:
        executionAddress = emuHelper.getExecutionAddress()  
        if (count > count_max):
            print("Emulation complete (count down).")
            break
        if end_addr == executionAddress:
            print("Emulation complete (end address).")
            break
        
        cinstr = getInstructionAt(executionAddress)
        
        print("{:#08d} 0x{} {}".format(count, executionAddress, cinstr))
        if cinstr.getMnemonicString() in handled_instructions:
            handled_instructions[cinstr.getMnemonicString()]()
            mainFunctionEntry = currentAddress
            mainFuncLong = int("0x{}".format(cinstr.getNext().getAddress()), 16)
            emuHelper.writeRegister(emuHelper.getPCRegister(), mainFuncLong)
            success = True
        else:
            success = emuHelper.step(monitor)
        for i in range(len(reg_filter)):
            creg = reg_filter[i]
            prev_val = reg_state[i]
            # print dir(emuHelper)
            reg_val = emuHelper.readRegister(creg)
            if reg_val != prev_val:
                print("                                      {} = {:#018x}".format(creg, reg_val))
                reg_state[i] = reg_val
        if (success == False):
            lastError = emuHelper.getLastError()
            printerr("Emulation Error: '{}'".format(lastError))
            break
        cycles += 1
        count += 1

for i in range(len(reg_filter)):
    creg = reg_filter[i]
    reg_val = emuHelper.readRegister(creg)
    print("  {} = {:#018x}".format(creg, reg_val))
    reg_state[i] = reg_val
