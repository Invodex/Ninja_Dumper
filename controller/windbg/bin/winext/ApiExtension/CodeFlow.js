"use strict";

//**************************************************************************
// CodeFlow.js:
//
// Uses the ApiExtension Code library to perform analysis about data flow
// within a function.
//
// Usage: !dflow <address>
//
//     Disassembles the function containing <address>, finds any instruction
//     in the control flow which influences the source operands of the instruction
//     at <address> and adds such instruction to the output collection.
//
// @TODO:
// 
//     - !dflow should be able to work without any symbolic information given a range
//       of assembly instructions to consider for the analysis
//

var __diagLevel = 0; // 1 is most important, increasingly less

function __diag(level)
{
    return (level <= __diagLevel);
}

class __TraceDataFlow
{
    constructor(disassembler, functionDisassembly, address)
    {
        this.__disassembler = disassembler;
        this.__functionDisassembly = functionDisassembly;
        this.__address = address;
    }

    toString()
    {
        var instr = this.__disassembler.DisassembleInstructions(this.__address).First();

        var str = "Traced data flow of " + this.__address.toString(16) + ": " + instr +") for source operands { ";
        var first = true;
        for (var operand of instr.Operands)
        {
            if (operand.Attributes.IsInput)
            {
                if (!first)
                {
                    str += ", ";
                }
                first = false;
                str += operand;
            }
        }
        str += " }";

        return str;
    }

    // __findBasicBlock:
    //
    // Finds a basic block containing the instruction at the given address.
    //
    __findBasicBlock(address)
    {
        var predicate = function(b) { return (address.compareTo(b.StartAddress) >= 0 && address.compareTo(b.EndAddress) < 0); } 
        return this.__functionDisassembly.BasicBlocks.First(predicate);
    }

    // __dumpRegisterSet:
    //
    // Diagnostic method to dump a register set.
    //
    __dumpRegisterSet(registerSet)
    {
        host.diagnostics.debugLog("    Register Set== ");
        for (var setReg of registerSet)
        {
            host.diagnostics.debugLog("'", this.__disassembler.GetRegister(setReg), "'(", setReg, "), ");
        }
        host.diagnostics.debugLog("\n");
    }

    // __addRegisterReferences:
    //
    // Adds a register (and all sub-registers) to a register set.
    //
    __addRegisterReferences(registerSet, reg)
    {
        registerSet.add(reg.Id);
        for(var subReg of reg.GetSubRegisters())
        {
            registerSet.add(subReg.Id);
        }
    }

    // __removeRegisterReferences:
    //
    // Removes a register (and all sub-registers) from a register set.
    //
    __removeRegisterReferences(registerSet, reg)
    {
        registerSet.delete(reg.Id);
        for(var subReg of reg.GetSubRegisters())
        {
            registerSet.delete(subReg.Id);
        }
    }

    // __hasRegisterReference
    //
    // Is the register 'reg' (or any sub-register) in the register set.
    //
    __hasRegisterReference(registerSet, reg)
    {
        if (__diag(3))
        {
            this.__dumpRegisterSet(registerSet);
            host.diagnostics.debugLog("    Comparison Set== '", reg, "'(", reg.Id, "), ");
            for( var subReg of reg.GetSubRegisters())
            {
                host.diagnostics.debugLog("'", subReg, "'(", subReg.Id, "), ");
            }
            host.diagnostics.debugLog("\n");
        }

        if (registerSet.has(reg.Id))
        {
            return true;
        }

        for (var subReg of reg.GetSubRegisters())
        {
            if (registerSet.has(subReg.Id))
            {
                return true;
            }
        }

        return false;
    }

    // __hasWriteOfMemory:
    //
    // Determines whether an operand in the set writes to memory in the memory reference set.
    //
    __hasWriteOfMemory(operandSet, memoryReferences)
    {
        for (var operand of operandSet)
        {
            var attrs = operand.Attributes;
            if (attrs.IsOutput && attrs.IsMemoryReference)
            {
                for (var ref of memoryReferences)
                {
                    if (__diag(5))
                    {
                        host.diagnostics.debugLog("    Checking '" + operand + "' against '" + ref + "'\n");
                    }

                    if (operand.ReferencesSameMemory(ref))
                    {
                        if (__diag(5))
                        {
                            host.diagnostics.debugLog("         Match on memory write!\n");
                        }
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // __writesToRegister
    //
    // Determines whether an operand is a write to a register in a register reference set.
    //
    __writesToRegister(instr, operandSet, registerReferences)
    {
        for (var operand of operandSet)
        {
            var attrs = operand.Attributes;
            if (attrs.IsOutput && attrs.IsRegister)
            {
                for (var reg of registerReferences)
                {
                    if (operand.UsesRegister(reg))
                    {
                        return true;
                    }
                }
            }
        }

        if (instr.Attributes.IsCall)
        {
            var retReg = instr.Attributes.ReturnRegister;

            if (__diag(2))
            {
                host.diagnostics.debugLog("Check for return register '", retReg, "' in instruction '", instr, "'\n");
            }
            
            if (retReg !== undefined)
            {
                if (__diag(2))
                {
                    host.diagnostics.debugLog("    Check id == ", retReg.Id, "\n");
                }

                if (this.__hasRegisterReference(registerReferences, retReg))
                {
                    return true;
                }
            }
        }

        return false;
    }

    // __kill:
    //
    // Removes a set of registers from the register set.
    //
    __kill(registerSet, registerReferences)
    {
        for(var reg of registerSet)
        {
            this.__removeRegisterReferences(registerReferences, reg);
        }
    }

    // __live:
    //
    // Makes a set of registers live in the register set.
    //
    __live(registerSet, registerReferences)
    {
        for (var reg of registerSet)
        {
            this.__addRegisterReferences(registerReferences, reg);
        }
    }

    // __killMemoryReference:
    //
    // Removes a memory reference from the set of live memory references.
    //
    __killMemoryReference(memRef, memoryReferences)
    {
        var i = 0;
        var len = memoryReferences.length;
        while (i < len)
        {
            if (memRef.ReferencesSameMemory(memoryReferences[i]))
            {
                memoryReferences.splice(i, 1);
                break;
            }
            ++i;
        }
    }

    // __liveMemoryReference:
    //
    // Adds a memory reference to the set of live memory references.
    //
    __liveMemoryReference(memRef, memoryReferences)
    {
        var i = 0;
        var len = memoryReferences.length;
        while (i < len)
        {
            if (memRef.ReferencesSameMemory(memoryReferences[i]))
            {
                return;
            }
            ++i;
        }
        memoryReferences.push(memRef);
    }

    // __addCallInputRegisters:
    //
    // Make an attempt to determine what were register inputs to the call and add them to the
    // lifetime set.  This is done by looking at the call target, disassembling it, looking
    // at the first instruction and whether any variables are live in registers as of the 
    // first instruction of the call target.
    //
    __addCallInputRegisters(instr, registerReferences)
    {
        if (__diag(4))
        {
            host.diagnostics.debugLog("Looking at call for inputs: '", instr, "'\n");
        }
   
        var callTarget;
        try
        {
            //
            // We may not be able to read this.  If we cannot, don't bother.
            //
            var opCount = instr.Operands.Count();
            if (opCount == 1)
            {
                var destOperand = instr.Operands.First();
                var attrs = destOperand.Attributes;

                if (attrs.IsImmediate)
                {
                    callTarget = destOperand.ImmediateValue;
                    if (__diag(2))
                    {
                        host.diagnostics.debugLog("Call has direct target: '", callTarget, "'\n");
                    }
                }
                else if (attrs.HasImmediate && attrs.IsMemoryReference && destOperand.Registers.Count() == 0)
                {
                    //
                    // @TODO: This should be sizeof(*) and *NOT* hard code to 64-bit.
                    //
                    var indirectCallTarget = destOperand.ImmediateValue;
                    if (__diag(2))
                    {
                        host.diagnostics.debugLog("Call has indirect target: '", indirectCallTarget, "'\n");
                    }

                    var tableRead = host.memory.readMemoryValues(indirectCallTarget, 1, 8, false);
                    callTarget = tableRead[0];

                    if (__diag(2))
                    {
                        host.diagnostics.debugLog("    Call destination read: '", callTarget, "'\n");
                    }
                }
            }
        }
        catch(exc1)
        {
        }

        try
        {
            //
            // We may not be able to read and disassemble the call target.  If we cannot, don't bother.
            //
            if (callTarget !== undefined)
            {
                //
                // We found the call target.  Disassemble it, get the first instruction, and go through all
                // live variables which are enregistered at this point.
                //
                var targetDis = this.__disassembler.DisassembleInstructions(callTarget);
                var firstInstr = targetDis.First();
                if (__diag(1))
                {
                    host.diagnostics.debugLog("Looking at call destination instruction '", firstInstr, "' for live variables.\n");
                }
                for (var liveVar of firstInstr.LiveVariables)
                {
                    if (liveVar.LocationKind == "Register" && liveVar.Offset == 0)
                    {
                        if (__diag(1))
                        {
                            host.diagnostics.debugLog("    Found call input register '", liveVar.Register, "'\n");
                        }
                        this.__addRegisterReferences(registerReferences, liveVar.Register);
                    }
                }
            }
        }
        catch(exc2)
        {
        }
    }

    // __reformLifetimes
    //
    // Performs any kills of written registers or memory references and 
    // adds all source registers and memory references to the set
    //
    // @TODO: If we pass the operandSet instead of instr, the second for...of will crash.  Fix!
    //
    __reformLifetimes(instr, registerReferences, memoryReferences)
    {
        if (instr.Attributes.IsCall)
        {
            var setCopy = new Set(registerReferences);
            for (var regId of setCopy)
            {
                var preserves = instr.PreservesRegisterValue(regId);
                if (__diag(3))
                {
                    host.diagnostics.debugLog("    Check preservation of (", regId, ") == ", preserves, "\n");
                }
                if (!preserves)
                {
                    this.__removeRegisterReferences(registerReferences, this.__disassembler.GetRegister(regId));
                }
            }
        }
        else
        {
            for (var operand of instr.Operands /*operandSet*/)
            {
                var attrs = operand.Attributes;
                if (attrs.IsOutput)
                {
                    if (attrs.IsRegister)
                    {
                        //
                        // Kill the registers.
                        //
                        this.__kill(operand.Registers, registerReferences);
                    }
                    else if (attrs.IsMemoryReference)
                    {
                        //
                        // Is there a memory reference in the array.
                        //
                        this.__killMemoryReference(operand, memoryReferences);
                    }
                }
            }
        }

        for (var operand of instr.Operands /*operandSet*/)
        {
            var attrs = operand.Attributes;
            if (attrs.IsInput)
            {
                this.__live(operand.Registers, registerReferences);
                if (attrs.IsMemoryReference)
                {
                    this.__liveMemoryReference(operand, memoryReferences);
                }
            }
        }

        //
        // If we have a call and can determine register passed values, do so.
        //
        if (instr.Attributes.IsCall)
        {
            this.__addCallInputRegisters(instr, registerReferences);
        }
    }

    // __dbgOutputSets:
    //
    // Diagnostic helper to output the live register and memory sets.
    //
    __dbgOutputSets(msg, registerReferences, memoryReferences)
    {
        if (__diag(2))
        {
            host.diagnostics.debugLog(msg, "\n");
            for (var regRef of registerReferences)
            {
                host.diagnostics.debugLog("    ", regRef, "\n");
            }
            for (var memRef of memoryReferences)
            {
                host.diagnostics.debugLog("    ", memRef, "\n");
            }
        }
    }

    // __scanBlockBackwards:
    //
    // For the given basic block, an instruction within that block
    // scan the block backwards looking for instructions that write to the source operands. 
    //
    // If one of the sources is written to, kill it from the scan.
    //
    *__scanBlockBackwards(basicBlock, instruction, registerReferences, memoryReferences, skipInstruction)
    {
        if (this.__exploredBlocks.has(basicBlock.StartAddress))
        {
            return;
        }
        this.__exploredBlocks.add(basicBlock.StartAddress);

        this.__dbgOutputSets("Scan: ", registerReferences, memoryReferences);

        //
        // Get the set of instructions in the basic block and walk them backwards.
        //
        var blockBackwards = basicBlock.Instructions.Reverse();
        var hitInstr = false;
        var address = instruction.Address;
        for (var instr of blockBackwards)
        {
            //
            // We have to get to the instruction in reverse first.
            //
            if (!hitInstr)
            {
                if (instr.Address.compareTo(address) == 0)
                {
                    hitInstr = true;
                }

                if (!hitInstr || skipInstruction)
                {
                    continue;
                }
            }

            //
            // This is in the basic block *BEFORE* the starting instruction.
            //
            if (__diag(2))
            {
                host.diagnostics.debugLog("Looking at instruction '", instr, "'\n");
            }

            //
            // If we have an instruction that writes to the same memory, it matches.
            //
            // If we have an instruction that writes to a referenced register, it matches -- add the source registers,
            //     and kill the destination registers.
            //
            var hasSameMemRef = this.__hasWriteOfMemory(instr.Operands, memoryReferences);
            var hasRegRef = this.__writesToRegister(instr, instr.Operands, registerReferences);

            if (__diag(5))
            {
                host.diagnostics.debugLog("    Has write: '", hasSameMemRef, "'\n");
                host.diagnostics.debugLog("    Has reg  : '", hasRegRef, "'\n");
            }

            if (hasSameMemRef || hasRegRef)
            {
                yield new host.indexedValue(instr, [instr.Address]);

                //
                // Once we have yielded that instruction, change the live register set.  Kill anything written
                // in instr and add anything read.
                //
                this.__reformLifetimes(instr, registerReferences, memoryReferences);
                this.__dbgOutputSets("Reform: ", registerReferences, memoryReferences);
            }
        }

        if (__diag(1))
        {
            host.diagnostics.debugLog("Traverse to blocks:\n");
            for (var inboundFlow of basicBlock.InboundControlFlows)
            {
                host.diagnostics.debugLog("    ", inboundFlow.LinkedBlock, "\n");
            }
        }

        //
        // The basic block has entries from other blocks, scan them.
        //
        for (var inboundFlow of basicBlock.InboundControlFlows)
        {
            var childSet = new Set(registerReferences);
            var childMem = memoryReferences.slice();
            yield* this.__scanBlockBackwards(inboundFlow.LinkedBlock, inboundFlow.SourceInstruction, childSet, childMem, false);
        }
    }

    // [Symbol.iterator]:
    //
    // Find all instructions in the data flow.
    //
    *[Symbol.iterator]()
    {
        this.__exploredBlocks = new Set();

        //
        // Find the starting instruction.  It is obviously part of the data flow.
        //
        var startingBlock = this.__findBasicBlock(this.__address);
        var startingInstruction = startingBlock.Instructions.getValueAt(this.__address);
        yield new host.indexedValue(startingInstruction, [startingInstruction.Address]);

        var memoryReferences = [];
        var registerReferences = new Set();

        if (__diag(2))
        {
            host.diagnostics.debugLog("Starting Instruction: ", startingInstruction, "\n");
        }
        for (var operand of startingInstruction.Operands)
        {
            if (__diag(5))
            {
                host.diagnostics.debugLog("Is '", operand, "' a source?\n");
            }
            var attrs = operand.Attributes;
            if (attrs.IsInput)
            {
                if (__diag(5))
                {
                    host.diagnostics.debugLog("    Yes\n");
                }
                if (attrs.IsMemoryReference)
                {
                    if (__diag(5))
                    {
                        host.diagnostics.debugLog("MemRef: ", operand, "\n");
                    }
                    memoryReferences.push(operand);
                }

                for (var reg of operand.Registers)
                {
                    if (__diag(5))
                    {
                        host.diagnostics.debugLog("RegRef: ", reg, "\n");
                    }
                    this.__addRegisterReferences(registerReferences, reg);
                }
            }
        }

        yield* this.__scanBlockBackwards(startingBlock, startingInstruction, registerReferences, memoryReferences, true);
    }

    // getDimensionality:
    //
    // Return the dimensionality of our indexer (1 -- by instruction address)
    //
    getDimensionality()
    {
        return 1;
    }

    // getValueAt:
    //
    // Return the instruction at the given address.  @TODO: It would be nice if this only allowed indexing
    // instructions in the data flow. 
    //
    getValueAt(addr)
    {
        var basicBlock = this.__findBasicBlock(this.__address);
        return basicBlock.Instructions.getValueAt(addr);
    }
}

// __getDisassemblyInfo:
//
// Gets information about where to disassemble for the data flow.  From the given address, this attempts
// to go back and find the start of the function to walk its dataflow.
//
function __getDisassemblyInfo(instrAddr)
{
    // 
    // If there is no specified address, grab IP.
    // @TODO: This should *NOT* directly reference RIP.  The stack frame should have an abstract IP/SP/FP
    //
    if (instrAddr === undefined)
    {
        if (__diag(5))
        {
            host.diagnostics.debugLog("Override to IP, instrAddr\n");
        }
        instrAddr = host.currentThread.Registers.User.rip;
    }

    //
    // If we can get the disassembly info from the new host.getModuleContainingSymbol, do so
    //
    var func;
    try
    {
        func = host.getModuleContainingSymbol(instrAddr);
    }
    catch(exc)
    {
    }

    if (func === undefined)
    {
        //
        // There should be a better way of doing this.  We should also use address instead!
        //
        var frame = host.currentThread.Stack.Frames[0];
        var frameStr = frame.toString();

        //
        // MODULE!NAME + OFFSET
        //
        var idx = frameStr.indexOf('+');
        if (idx != -1)
        {
            frameStr = frameStr.substr(0, idx).trim();
        }

        //
        // MODULE!NAME
        //
        var bangIdx = frameStr.indexOf('!');
        if (idx == -1)
        {
            throw new Error("Unable to find function name to disassemble");
        }

        var moduleName = frameStr.substr(0, bangIdx);
        var funcName = frameStr.substr(bangIdx + 1);

        if (__diag(2))
        {
            host.diagnostics.debugLog("ModuleName = '", moduleName, "'; funcName = '", funcName, "'\n");
        }

        func = host.getModuleSymbol(moduleName, funcName);
    }

    return { function: func, address: instrAddr };
}

// __CodeExtension:
//
// Provides an extension on Debugger.Utility.Code
//
class __CodeExtension
{
    TraceDataFlow(address)
    {
        var disassemblyInfo = __getDisassemblyInfo(address);
        var disassembler = host.namespace.Debugger.Utility.Code.CreateDisassembler();
        var funcDisassembly = disassembler.DisassembleFunction(disassemblyInfo.function, true);
        return new __TraceDataFlow(disassembler, funcDisassembly, disassemblyInfo.address);
    }
}

// __traceDataFlow:
//
// Function alias for !dflow
//
function __traceDataFlow(address)
{
    return host.namespace.Debugger.Utility.Code.TraceDataFlow(address);
}

// __disassembleCode:
//
// Function alias for !dis
//
function __disassembleCode(addressObj)
{
    var dbg = host.namespace.Debugger;

    if (addressObj === undefined)
    {
        //
        // @TODO:
        // This is *NOT* generic.  This is *DBGENG* specific.  We should get an IP from the stack.
        //
        addressObj = dbg.State.PseudoRegisters.RegisterAliases.ip.address;
    }

    return dbg.Utility.Code.CreateDisassembler().DisassembleInstructions(addressObj);
}

// __InstructionExtension:
//
// Provides an extension on an instruction
//
class __InstructionExtension
{
    get SourceDataFlow()
    {
        return __traceDataFlow(this.Address);
    }
}

// initializeScript:
//
// Initializes our script.  Registers our extensions and !dflow alias.
//
function initializeScript()
{
    return [new host.apiVersionSupport(1, 2),
            new host.namespacePropertyParent(__CodeExtension, "Debugger.Models.Utility", "Debugger.Models.Utility.Code", "Code"),
            new host.namedModelParent(__InstructionExtension, "Debugger.Models.Utility.Code.Instruction"),
            new host.functionAlias(__traceDataFlow, "dflow"),
            new host.functionAlias(__disassembleCode, "dis")];
}

// SIG // Begin signature block
// SIG // MIIl9wYJKoZIhvcNAQcCoIIl6DCCJeQCAQExDzANBglg
// SIG // hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor
// SIG // BgEEAYI3AgEeMCQCAQEEEBDgyQbOONQRoqMAEEvTUJAC
// SIG // AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg
// SIG // 8Vd5mJ3w6q+ClnHrnQIoaqCXDHQ0K4ZNgLaaX8x0Gjag
// SIG // ggt2MIIE/jCCA+agAwIBAgITMwAABDp15S+eCymYHgAA
// SIG // AAAEOjANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJV
// SIG // UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
// SIG // UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
// SIG // cmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBT
// SIG // aWduaW5nIFBDQSAyMDEwMB4XDTIxMDkwMjE4MjU1OVoX
// SIG // DTIyMDkwMTE4MjU1OVowdDELMAkGA1UEBhMCVVMxEzAR
// SIG // BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
// SIG // bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
// SIG // bjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
// SIG // MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
// SIG // mN2UakdrQlpc82AXwhPsTB/YfRgnrtOGzr8CNQrJhoHZ
// SIG // UNQeX2wjyfKVf1Q5us+AHKQssxWPSIx0y770P3Fgyfcb
// SIG // q6iv+8dnfi401KDZ3tobw7NGTy4ZkUTxPRdt28NdDqoE
// SIG // UGJNDsQ20E1ssFrjEXNFUP0c6McBWaiEihGrk2BMboNM
// SIG // g/dvhFsc2j+wWe9jhMpfKYAmUGYYFmntC4z0ydVkqlmG
// SIG // ILbfbnxTw4KNQuXOPPmyKF2NPwLWvMa6R9xB98Qwo7zC
// SIG // 9HOeJebMTQizbxb5WdW1xn8axF70M+MkK8sOj835fMOw
// SIG // tvLSXh+D+gwo9tx3LVS1GOCLwQ+kverD/QIDAQABo4IB
// SIG // fTCCAXkwHwYDVR0lBBgwFgYKKwYBBAGCNz0GAQYIKwYB
// SIG // BQUHAwMwHQYDVR0OBBYEFE+obV3ibJMpfkCNXw2QjO+5
// SIG // n90rMFQGA1UdEQRNMEukSTBHMS0wKwYDVQQLEyRNaWNy
// SIG // b3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
// SIG // FjAUBgNVBAUTDTIzMDg2NSs0NjczOTkwHwYDVR0jBBgw
// SIG // FoAU5vxfe7siAFjkck619CF0IzLm76wwVgYDVR0fBE8w
// SIG // TTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29t
// SIG // L3BraS9jcmwvcHJvZHVjdHMvTWljQ29kU2lnUENBXzIw
// SIG // MTAtMDctMDYuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggr
// SIG // BgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29t
// SIG // L3BraS9jZXJ0cy9NaWNDb2RTaWdQQ0FfMjAxMC0wNy0w
// SIG // Ni5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsF
// SIG // AAOCAQEAWWyUufc3NL25D3JgmCKYeXNXsPzigP595Uyk
// SIG // J3IcZxcOzDy8tpRvau/cG3WetxI4ghf/Cgf11gcenQAJ
// SIG // OD9clIznjQiCeo/XDYxENMW8OeriZAdepVeqvdDlpgo9
// SIG // N9faidMcOrYmtK0eXPctDUtMPdUvOs7Swujv8LPsNt9N
// SIG // zgplDR9AbG37PmCMHb44BYpiHEqjH8KcLM4UmvxV7vP8
// SIG // FLy/hAABPs7c9PK1zOfP9OPxiCfWvdJjxPX3K2Q6zsTn
// SIG // +d2/rYwXm3jse53Cr373Oqtrk/roYyAmTTgTK14mFQ+I
// SIG // udB8VCgXfU2nJV6ubdz4OkyFjb9GF1qlqHU4mfShEDCC
// SIG // BnAwggRYoAMCAQICCmEMUkwAAAAAAAMwDQYJKoZIhvcN
// SIG // AQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
// SIG // YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
// SIG // VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNV
// SIG // BAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1
// SIG // dGhvcml0eSAyMDEwMB4XDTEwMDcwNjIwNDAxN1oXDTI1
// SIG // MDcwNjIwNTAxN1owfjELMAkGA1UEBhMCVVMxEzARBgNV
// SIG // BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
// SIG // HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEo
// SIG // MCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQ
// SIG // Q0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
// SIG // AQoCggEBAOkOZFB5Z7XE4/0JAEyelKz3VmjqRNjPxVhP
// SIG // qaV2fG1FutM5krSkHvn5ZYLkF9KP/UScCOhlk84sVYS/
// SIG // fQjjLiuoQSsYt6JLbklMaxUH3tHSwokecZTNtX9LtK8I
// SIG // 2MyI1msXlDqTziY/7Ob+NJhX1R1dSfayKi7VhbtZP/iQ
// SIG // tCuDdMorsztG4/BGScEXZlTJHL0dxFViV3L4Z7klIDTe
// SIG // XaallV6rKIDN1bKe5QO1Y9OyFMjByIomCll/B+z/Du2A
// SIG // EjVMEqa+Ulv1ptrgiwtId9aFR9UQucboqu6Lai0FXGDG
// SIG // tCpbnCMcX0XjGhQebzfLGTOAaolNo2pmY3iT1TDPlR8C
// SIG // AwEAAaOCAeMwggHfMBAGCSsGAQQBgjcVAQQDAgEAMB0G
// SIG // A1UdDgQWBBTm/F97uyIAWORyTrX0IXQjMubvrDAZBgkr
// SIG // BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
// SIG // AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV
// SIG // 9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEug
// SIG // SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtp
// SIG // L2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0w
// SIG // Ni0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
// SIG // BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
// SIG // L2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNy
// SIG // dDCBnQYDVR0gBIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEw
// SIG // PQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0
// SIG // LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYI
// SIG // KwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwA
// SIG // aQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJ
// SIG // KoZIhvcNAQELBQADggIBABp071dPKXvEFoV4uFDTIvwJ
// SIG // nayCl/g0/yosl5US5eS/z7+TyOM0qduBuNweAL7SNW+v
// SIG // 5X95lXflAtTx69jNTh4bYaLCWiMa8IyoYlFFZwjjPzwe
// SIG // k/gwhRfIOUCm1w6zISnlpaFpjCKTzHSY56FHQ/JTrMAP
// SIG // MGl//tIlIG1vYdPfB9XZcgAsaYZ2PVHbpjlIyTdhbQfd
// SIG // UxnLp9Zhwr/ig6sP4GubldZ9KFGwiUpRpJpsyLcfShoO
// SIG // aanX3MF+0Ulwqratu3JHYxf6ptaipobsqBBEm2O2smmJ
// SIG // BsdGhnoYP+jFHSHVe/kCIy3FQcu/HUzIFu+xnH/8IktJ
// SIG // im4V46Z/dlvRU3mRhZ3V0ts9czXzPK5UslJHasCqE5XS
// SIG // jhHamWdeMoz7N4XR3HWFnIfGWleFwr/dDY+Mmy3rtO7P
// SIG // J9O1Xmn6pBYEAackZ3PPTU+23gVWl3r36VJN9HcFT4XG
// SIG // 2Avxju1CCdENduMjVngiJja+yrGMbqod5IXaRzNij6TJ
// SIG // kTNfcR5Ar5hlySLoQiElihwtYNk3iUGJKhYP12E8lGhg
// SIG // Uu/WR5mggEDuFYF3PpzgUxgaUB04lZseZjMTJzkXeIc2
// SIG // zk7DX7L1PUdTtuDl2wthPSrXkizON1o+QEIxpB8QCMJW
// SIG // nL8kXVECnWp50hfT2sGUjgd7JXFEqwZq5tTG3yOalnXF
// SIG // MYIZ2TCCGdUCAQEwgZUwfjELMAkGA1UEBhMCVVMxEzAR
// SIG // BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
// SIG // bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
// SIG // bjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmlu
// SIG // ZyBQQ0EgMjAxMAITMwAABDp15S+eCymYHgAAAAAEOjAN
// SIG // BglghkgBZQMEAgEFAKCCAQQwGQYJKoZIhvcNAQkDMQwG
// SIG // CisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
// SIG // AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKIX4Udx4U4A
// SIG // dMn9MnuHG+bn5tt2e42s/w5Ec/DcmBeMMDwGCisGAQQB
// SIG // gjcKAxwxLgwsc1BZN3hQQjdoVDVnNUhIcll0OHJETFNN
// SIG // OVZ1WlJ1V1phZWYyZTIyUnM1ND0wWgYKKwYBBAGCNwIB
// SIG // DDFMMEqgJIAiAE0AaQBjAHIAbwBzAG8AZgB0ACAAVwBp
// SIG // AG4AZABvAHcAc6EigCBodHRwOi8vd3d3Lm1pY3Jvc29m
// SIG // dC5jb20vd2luZG93czANBgkqhkiG9w0BAQEFAASCAQCN
// SIG // AXBsdfz0RRpJn+gkvCWorrnq9q5+gHIS0Q6LooQrOr8Z
// SIG // a121sinoW+Ez7QWmM4yRBPdNmBVN9uoPdPov28Jt3gu3
// SIG // 5zjS3Nv+N7NFnpWgICS1kpQ1te8tSB50nkbYSysNx5fw
// SIG // SZZ1zcuAdd3rGjlxn2tHfS/xv+yJl55gyxyTn9sxOxpx
// SIG // v1HZp4RLw6WD119EZaOJ4aMVJYCZ2qmCF8RAGeUOk6l3
// SIG // PCHKIeUCqU9/YmwWs5tw5pwAFWD2hysWuQ42BaKrm79Z
// SIG // 13Hyi3yq8DlMgyuhc69v8Dlx3klL5vFsc3Z0R/mwnZ1J
// SIG // z2ET8kGuqSKgtqnYh8l3LlvfVhUlR3NpoYIXDDCCFwgG
// SIG // CisGAQQBgjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW
// SIG // 5TCCFuECAQMxDzANBglghkgBZQMEAgEFADCCAVUGCyqG
// SIG // SIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEEAYRZ
// SIG // CgMBMDEwDQYJYIZIAWUDBAIBBQAEIJVX4f1bWhojaI3j
// SIG // EvOXqyZGUrogoYtTpKNMBKcyRfBbAgZia0pdDDsYEzIw
// SIG // MjIwNTA2MjIzMjQwLjAzNVowBIACAfSggdSkgdEwgc4x
// SIG // CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
// SIG // MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
// SIG // b3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jv
// SIG // c29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYD
// SIG // VQQLEx1UaGFsZXMgVFNTIEVTTjo2MEJDLUUzODMtMjYz
// SIG // NTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
// SIG // U2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABpllF
// SIG // gzlNnutLAAEAAAGmMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
// SIG // BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
// SIG // DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
// SIG // ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
// SIG // dCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMDMwMjE4
// SIG // NTEyMVoXDTIzMDUxMTE4NTEyMVowgc4xCzAJBgNVBAYT
// SIG // AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
// SIG // EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
// SIG // cG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVy
// SIG // YXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFs
// SIG // ZXMgVFNTIEVTTjo2MEJDLUUzODMtMjYzNTElMCMGA1UE
// SIG // AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
// SIG // AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANmY
// SIG // v3tSI+fJ/NQJnjz7JvCnc+Xm0rKoe9YKD4MvMYCul7eg
// SIG // drT/zv5vFbQgjNQ74672fNweaztkR65V8y29u5PL2sf0
// SIG // 1p+uche0Zu4tSig+GsQ6ZQl9tjPRAY/3ITBHDeIYyvq8
// SIG // Wne9+7NoPLhxDSO6dtX7YCuQ4zcTP3SE6MvB4b5Nighd
// SIG // tvoZVaYk1lXpjUTfdmKoX1ABq1sJbULSnSi0Qd4vvl3m
// SIG // Z9jxwv9dR/nlZP62lrZYZq7LPtHD6BlmclB5PT89DnSm
// SIG // 1sjaZnFHrKzOsmq5GlmL5SFugCCZOoKz133FJeQaFMcX
// SIG // BZSCQjNABWBbHIRCE1ysHHG83DdonRmnC8EOlYeRwTWz
// SIG // /QCz6q0riOIbYyC/A2BgUEpu9/9EymrTsyMr2/zS8GdE
// SIG // ybQ5W7f0WrcrmKB/Y62+g6TmfOS8NtU+L1jGoKNG6Q5R
// SIG // lfJwZu8J/Q9dl4OxyHKuy78+wm6HsF7uAizpsWh63UUa
// SIG // oK/OGQiBG3NJ+kef5eWpnva4ZJfhAnqYTAZD1uHgf8Vf
// SIG // Qjnl0BB2YXzK9WaTqde8d+8qCxVKr5hJYvbO+X3+2k5P
// SIG // CirUK/SboreX+xUhVaQEhVDYqlatyPttI7Z2IrkhMzwF
// SIG // vc+p0QeyMiNmo2cBZejx8icDOcUidwymDUYqGPE7MA8v
// SIG // tKW3feeSSYJsCEkuUO/vAgMBAAGjggE2MIIBMjAdBgNV
// SIG // HQ4EFgQUOlQhO/zGlqK99UkNL/Gu/AryN9gwHwYDVR0j
// SIG // BBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0f
// SIG // BFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQu
// SIG // Y29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1T
// SIG // dGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUF
// SIG // BwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
// SIG // aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3Nv
// SIG // ZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
// SIG // cnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEF
// SIG // BQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAgMDxWDTpGqLn
// SIG // FoPhm/iDfwHGF8xr2NbrJl8egEg2ThTJsTf0wBE+ZQsn
// SIG // YfrRmXBbe6sCXLVN70qPuI+OEbN5MOai7Bue1/4j5VTk
// SIG // WquH5GZeVat2N+dD7lSUWp0dU8j+uBhBL5GFSmoDVVm+
// SIG // zW2GR2juPI1v254AJTb2l458anlkJjGvmYn2BtRS13h/
// SIG // wDR7hrQaI7BgdyHWAV5+HEj5UhrIrrvtwJiivSaUEA3q
// SIG // K6ZK/rZIQv/uORDkONw+2pHHIE1SXm/WIlhrVS2HIogf
// SIG // r3JjqvZion6LJSD741j8xVDLiClwAbspHoVFjxtxBcMj
// SIG // qPx6aWCJS8vjSoTnhkV4PO55mqsM7Q8XQRGQhA7w4zNQ
// SIG // OJu9kD4xFdYpPUmLN/daIcEElofBjGz+sEd1B4yqqIk3
// SIG // u2G4VygTXFmthL8chSo7r+GIvTqWKhSA/sanS4N3jCgC
// SIG // Ce3FTSJsp4g5nwavLvWAtzcOIvSRorGmAeN0m2wgzBK9
// SIG // 5T/qgrGGDXSos1JNDWRVBnP0qsw1Qoq5G0D8hxvQPs3X
// SIG // 43KBv1GJl0wo5rcC+9OMWxJlB63gtToQsA1CErYoYLMZ
// SIG // tUzJL74jwZk/grpHEQhIhB3sneC8wzGKJuft7YO/HWCp
// SIG // uwdChIjynTnBh+yFGMdg3wRrIbOcw/iKmXZopMTQMOcm
// SIG // IeIwJAezA7AwggdxMIIFWaADAgECAhMzAAAAFcXna54C
// SIG // m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
// SIG // VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
// SIG // A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
// SIG // IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQg
// SIG // Um9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAe
// SIG // Fw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwx
// SIG // CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
// SIG // MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
// SIG // b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
// SIG // c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkq
// SIG // hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciEL
// SIG // eaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9
// SIG // uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cy
// SIG // wBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTeg
// SIG // Cjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7
// SIG // uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
// SIG // 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPg
// SIG // yY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy
// SIG // 1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEe
// SIG // HT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/b
// SIG // fV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP
// SIG // 8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJo
// SIG // LhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6
// SIG // EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1
// SIG // GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N
// SIG // +VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacau
// SIG // e7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcV
// SIG // AQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+
// SIG // gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP0
// SIG // 5dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdM
// SIG // g30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1p
// SIG // Y3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
// SIG // eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYB
// SIG // BAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGG
// SIG // MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZW
// SIG // y4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmg
// SIG // R4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9j
// SIG // cmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYt
// SIG // MjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcw
// SIG // AoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
// SIG // ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQw
// SIG // DQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb
// SIG // 4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRs
// SIG // fNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2
// SIG // LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2Rje
// SIG // bYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihV
// SIG // J9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8
// SIG // DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
// SIG // FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2
// SIG // kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0
// SIG // SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5b
// SIG // RAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beu
// SIG // yOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9
// SIG // y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJ
// SIG // jXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW
// SIG // 4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ
// SIG // 8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOh
// SIG // cGbyoYIC0jCCAjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNV
// SIG // BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
// SIG // VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
// SIG // Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBP
// SIG // cGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1U
// SIG // aGFsZXMgVFNTIEVTTjo2MEJDLUUzODMtMjYzNTElMCMG
// SIG // A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
// SIG // ZaIjCgEBMAcGBSsOAwIaAxUAanQzrZW9TB93Ve7Pa4UP
// SIG // ao2ffK2ggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
// SIG // A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
// SIG // ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
// SIG // MSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
// SIG // Q0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOYfq78wIhgP
// SIG // MjAyMjA1MDYxODE0MjNaGA8yMDIyMDUwNzE4MTQyM1ow
// SIG // dzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5h+rvwIBADAK
// SIG // AgEAAgIingIB/zAHAgEAAgIR6jAKAgUA5iD9PwIBADA2
// SIG // BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAow
// SIG // CAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
// SIG // BQUAA4GBABearwgBcZsI3mwjn/EA+BfVIOlMWU6HIoHf
// SIG // NmsTkXK9fHioV/YBR+OO1p05ufYMRx7CdtPEbGyeUjhM
// SIG // 1lIWspRgIJ0X60J76N3XBJrwPmevb/cYpAV/6L1krKHi
// SIG // MR1MjbfMwYpxdJZphy5FFTncByrggCXYDfYA1keXJrTU
// SIG // r86rMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMx
// SIG // EzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
// SIG // ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
// SIG // dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
// SIG // bXAgUENBIDIwMTACEzMAAAGmWUWDOU2e60sAAQAAAaYw
// SIG // DQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzEN
// SIG // BgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgMRXU
// SIG // r/Bxv00ULjDm9rkerF2VU8IKY0e/tJvI66h/c4EwgfoG
// SIG // CyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCCDCxmLwz90
// SIG // fWvhMKbJTAQaKt3DoXeiAhfp8TD9tgSrDTCBmDCBgKR+
// SIG // MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
// SIG // dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
// SIG // aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
// SIG // Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB
// SIG // pllFgzlNnutLAAEAAAGmMCIEIL4L72N37IuAnDUVf5JU
// SIG // dLX2Elvw3rb1oxFcJwFm6k7JMA0GCSqGSIb3DQEBCwUA
// SIG // BIICAIdMKqruO3Fm/5OITyLCsGPiEOy9yZQ76cFgZQ9A
// SIG // ZXMyJCfr27mNiUX+mGWFRv1kMQM5vf24E0G8WKTDOra7
// SIG // oo+vg5Z33A/dQKc2h4NtJwKYgtQIg258HYiFqIBfAvpc
// SIG // 5Bv/pS9nmu1NLNd90Wwn/FmbGDBIltDateNOYRFofoch
// SIG // LsfPYzyCXIWbBOJ7SAozglRpaWxGTZO+5rWMkWIhgqrb
// SIG // zo/tJXvwdQYLkqgKrrXRC+w8CiPZaoLgWIws1hr4HKqs
// SIG // 1kYwh1Yr1Y/TRSNz2i6gC9iwedDgf9sVhcSyyb6Atwpe
// SIG // 3LAffK2h+yksC7Lfd2CzywXHdoXkoD3RxWcEADAPlS9+
// SIG // 3dnAyZLeWs9mNhgwdIdL08DIJyfDob3i2g6pSkSGb0AP
// SIG // wf9ERb6N6TL6f94gYnJVxFgDqXRq+9oHPv+URfIH0Jw3
// SIG // JGG7b7c6J2/jUio3i8OI6p7j6ltqYmqkAFPrDkxQTiu+
// SIG // UAf2hBz5BvYeatbkjaNvFMbCHs1ckHynLYDRcG7Z7cKH
// SIG // HpJkdIlHUVGT9mLN71IQ2vfTG4cvNtYtkzoZm3F4D0oy
// SIG // XMJ+rAr55q9jljS38+oL7BUbz99kHwUY5tr/W8RwFUhg
// SIG // R7UIuYf99gcEbyFdNFzyeq7dJz0Q9wmLFj5Qs+Tc4Gtx
// SIG // dOIHthcemOb0TbYkM1qV1V6rR1cm
// SIG // End signature block
