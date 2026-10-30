//Ghidra script for analyzing VTables in the libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import com.sad.pvz2.PvZ2BaseScript;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class VTableAnalysis extends PvZ2BaseScript {
  public static VTableAnalysis script = null;
  public static String CLASS_NAME;

  @Override
  protected void run() {
    init("26.0.0", "1.4.244592", "vtable_analysis.log");
    logHeader("PvZ2 VTable Analyzer", SCRIPT_VERSION, GAME_VERSION);

    script = this;
    ProgramSelection selection = currentSelection;
    int index = 0;
    if (selection == null || selection.isEmpty()) return;

    Address currAddr = selection.getMinAddress();
    while (currAddr.getOffset() <= selection.getMaxAddress().getOffset()) {
      analyzeAddr(currAddr, index);
      if (CLASS_NAME == null) break;
      currAddr = currAddr.add(PTR_SIZE);
      index++;
    }
  }

  public static void analyzeAddr(Address addr, int index) {
    if (addr == null) return;
    Address vfuncAddr = getTypedValue(Address.class, addr);
    if (vfuncAddr == null) return;

    Function func = listing.getFunctionAt(vfuncAddr);
    if (func == null) {
      func = script.createFunction(vfuncAddr, null);
      log("Made function at address 0x" + vfuncAddr);
    }

    // Continue only if function signature isn't DEFAULT
    if (func.getSignatureSource() != SourceType.DEFAULT) return;

    switch (index) {
      case 0 -> CLASS_NAME = analyzeGetType(func);
    }

    log(CLASS_NAME);
    log(func + " 0x" + vfuncAddr);
  }

  public static String analyzeGetType(Function func) {
    String className = getFunctionStringRefs(func);
    if (className != null) {
      Address instanceAddr = getReturnTargetAddress(func);
      log(instanceAddr + "");
      setFuncName(func, className, "GetType");
      return className;
    }
    
    // Analyze the called function if first function is just a wrapper to SGetType    
    Function calledFunc = getCalledFunction(func);
    className = getFunctionStringRefs(calledFunc);
    
    if (className == null)
      return null;

    return className;
  }

  public static Address getReturnTargetAddress(Function func) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), false);

    for (Instruction instr : instrs) {
      
    }
    return null;
  }

  public static boolean isDataAddress(Address addr) {
    if (addr == null || !mem.contains(addr)) return false;
    if (listing.getFunctionAt(addr) != null) return false;
    var block = mem.getBlock(addr);
    return block != null && !block.isExecute();
  }

  public static Function getCalledFunction(Function func) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), true);
    for (Instruction instr : instrs) {
      if (instr.getFlowType().isCall()) {
        for (Reference ref : instr.getReferencesFrom()) {
          Address targetAddr = ref.getToAddress();
          Function calledFunc = listing.getFunctionAt(targetAddr);
          if (calledFunc == null) continue;
          return calledFunc;
        }
      }
    }
    return null;
  }

  public static String getFunctionStringRefs(Function func) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), false);

    for (Instruction instr : instrs) {
      for (Reference ref : instr.getReferencesFrom()) {
        Address targetAddr = ref.getToAddress();
        if (targetAddr == null || !program.getMemory().contains(targetAddr)) continue;

        String strVal = getTypedValue(String.class, targetAddr);
        if (strVal == null) continue;
        return strVal;
      }
    }
    return null;
  }

  public static Data getData(Address addr) {
    return listing.getDataAt(addr);
  }

  public static <T> T getTypedValue(Class<T> clazz, Address addr) {
    Data data = listing.getDataAt(addr);
    if (data == null) return null;

    Object value = data.getValue();
    if (value == null || !clazz.isInstance(value)) return null;
    return clazz.cast(value);
  }

  public static void setFuncName(Function func, String namespace, String name) {
    try {
      if (namespace != null) { 
        Namespace ns = NamespaceUtils.createNamespaceHierarchy(namespace, null, program, SourceType.USER_DEFINED);
        func.setParentNamespace(ns);
      }
      func.setName(name, SourceType.USER_DEFINED);
    }
    catch (DuplicateNameException e) {
      error("DuplicateNameException", e);
    }
    catch (InvalidInputException e) {
      error("InvalidInputException", e);
    }
    catch (CircularDependencyException e) {
      error("CircularDependencyException", e);
    }
  }
}
