//Ghidra test script 
//@author sad
//@category PvZ2 Tools
//@keybinding ctrl g
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.util.HashMap;
import java.util.Map;

import com.sad.pvz2.PvZ2BaseScript;

import ghidra.app.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;

public class TestScript extends PvZ2BaseScript {
  private static final Map<String, Namespace> namespaceCache = new HashMap<>();

  @Override
  protected void run() {
    init("26.0.0", "1.4.244592", "test.log", true);
    logHeader("PvZ2 VTable Analyzer", SCRIPT_VERSION, GAME_VERSION);

    Function curFun = getFunctionAt(this.currentAddress);
    // Data data = getDataAt(this.currentAddress);

    ctor(curFun);

    // Clear cache
    namespaceCache.clear();
  }

  public static void ctor(Function func) {
    Function ctor = getFunctionCallRefs(func, 3);
    String name = getFunctionStringRefs(func);
    setFunctionName(ctor, name, name);
  }

  public static void SGetType(Function func) {
    String className = getFunctionStringRefs(func);
    setFunctionName(func, className, "SGetType");
  }

  public static Function getFunctionCallRefs(Function func, int targetIndex) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), false);

    int count = 0;
    for (Instruction instr : instrs) {
      for (Reference ref : instr.getReferencesFrom()) {
        if (!isFunction(ref.getToAddress())) continue;
        
        // if (instr.getFlowType().isCall()) {
          Address targetAddr = ref.getToAddress();
          Function calledFunc = listing.getFunctionAt(targetAddr);
          if (calledFunc == null) continue;

          count++;

          if (count == targetIndex) return calledFunc;
        // }
      }
    }
    return null;
  }

  public static boolean isFunction(Address addr) {
    if (addr == null) return false;

    Function calledFunc = listing.getFunctionAt(addr);
    if (calledFunc != null) return true;

    return false;
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

  public static <T> T getTypedValue(Class<T> clazz, Address addr) {
    Data data = listing.getDataAt(addr);
    if (data == null) return null;

    Object value = data.getValue();
    if (value == null || !clazz.isInstance(value)) return null;
    return clazz.cast(value);
  }

  public static void setFunctionName(Function func, String namespace, String name) {
    try {
      if (namespace != null) {
        Namespace ns = getOrCreateNamespace(namespace);
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

  public static Namespace getOrCreateNamespace(String name) {
    if (name == null || name.isEmpty()) return program.getGlobalNamespace();
    if (namespaceCache.containsKey(name)) return namespaceCache.get(name);

    try {
      Namespace ns = NamespaceUtils.createNamespaceHierarchy(
        name, 
        program.getGlobalNamespace(), 
        program, 
        SourceType.USER_DEFINED
      );
      namespaceCache.put(name, ns);
      return ns;
    }
    catch (InvalidInputException e) {
      error("InvalidInputException", e);
      return program.getGlobalNamespace();
    }
  }
}
