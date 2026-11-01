//Ghidra script for analyzing VTables in the libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.util.HashMap;
import java.util.Map;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.util.StructUtil;

import ghidra.app.util.NamespaceUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class VTableAnalysis extends PvZ2BaseScript {
  public static VTableAnalysis instance = null;

  public static String CLASS_NAME;
  public static long CLASS_SIZE;

  private static final Map<String, Namespace> namespaceCache = new HashMap<>();

  @Override
  protected void run() {
    init("26.0.0", "1.4.244592", "vtable_analysis.log");
    logHeader("PvZ2 VTable Analyzer", SCRIPT_VERSION, GAME_VERSION);
    instance = this;
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

    // Create VTable Struct
    String categoryPathStr = CLASS_NAME.replace("::", "/");
    CategoryPath categoryPath = new CategoryPath(PVZ2_CATEGORY, categoryPathStr);

    StructureDataType vtable = StructUtil.getOrCreateStructure(dtm, categoryPath, CLASS_NAME + "VTable", b -> {
      Address address = selection.getMinAddress();
      while (address.getOffset() <= selection.getMaxAddress().getOffset()) {
        b.add(UNDEFINED_POINTER_TYPE);
        address = address.add(PTR_SIZE);
      }
    });
    changeDataType(selection.getMinAddress(), vtable);

    // Create Class Struct
    StructUtil.getOrCreateStructure(dtm, categoryPath, CLASS_NAME, b -> {
      b.add(new PointerDataType(vtable), "vtable", "");
      for (int i = PTR_SIZE; i < CLASS_SIZE; i += PTR_SIZE) {
        b.add(UNDEFINED_POINTER_TYPE);
      }
    });

    // Clear cache
    namespaceCache.clear();
  }

  public static void analyzeAddr(Address addr, int index) {
    if (addr == null) return;
    Address vfuncAddr = getTypedValue(Address.class, addr);
    if (vfuncAddr == null) return;

    Function func = listing.getFunctionAt(vfuncAddr);
    if (func == null) {
      func = instance.createFunction(vfuncAddr, null);
      log("Made function at address 0x" + vfuncAddr);
    }

    // Continue only if function signature isn't DEFAULT
    if (func.getSignatureSource() != SourceType.DEFAULT) return;

    switch (index) {
      case 0 -> analyzeGetType(func);
      case 1 -> analyzeIsAbstract(func);
      case 2 -> setFuncName(func, CLASS_NAME, "~" + CLASS_NAME);
      case 3 -> setFuncName(func, CLASS_NAME, "Destroy");
    }

    log("[0x" + vfuncAddr + "] " + func);
  }

  public static void analyzeIsAbstract(Function func) {
    setFuncName(func, CLASS_NAME, "IsAbstract");
    setReturnType(func, BooleanDataType.dataType);
  }

  public static void analyzeGetType(Function func) {
    CLASS_NAME = getFunctionStringRefs(func);
    Function targetFunc = func;
    String funcName = "GetType";

    // Analyze the called function if first function is just a wrapper to SGetType
    if (CLASS_NAME == null) {
      targetFunc = getCalledFunction(func);
      if (targetFunc == null) return;
      
      CLASS_NAME = getFunctionStringRefs(targetFunc);
      if (CLASS_NAME == null) return;
      
      funcName = "SGetType";
    }
    
    setFuncName(targetFunc, CLASS_NAME, funcName);
    makeInstanceAddr(targetFunc, CLASS_NAME);
    makeNewFunction(targetFunc, CLASS_NAME);
    
    setFuncName(func, CLASS_NAME, "GetType");
  }

  public static void makeNewFunction(Function func, String className) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), false);
    int funcCount = 0;
    for (Instruction instr : instrs) {
      for (Reference ref : instr.getReferencesFrom()) {
        Address toAddr = ref.getToAddress();
        if (toAddr == null) continue;

        Symbol sym = symTab.getPrimarySymbol(toAddr);
        if (sym == null || sym.getSymbolType() != SymbolType.FUNCTION) continue;

        if (funcCount == 1) {
          Function newFunc = listing.getFunctionAt(toAddr);
          setFuncName(newFunc, className, "new");
          getClassSize(newFunc);
          return;
        }

        funcCount++;
      }
    }
  }

  // Function to search the first mov r0,0xN and return 0xN from it
  public static void getClassSize(Function func) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), true);
    for (Instruction instr : instrs) {
      if (!instr.getMnemonicString().equals("mov")) continue;
      if (!(instr.getOpObjects(1)[0] instanceof Scalar scalar)) continue;
      CLASS_SIZE = scalar.getValue();
      return;
    }
    CLASS_SIZE = 0x1;
  }

  public static void makeInstanceAddr(Function func, String className) {
    InstructionIterator instrs = listing.getInstructions(func.getBody(), false);

    for (Instruction instr : instrs) {
      if (!instr.getMnemonicString().equals("ldr")) continue;

      for (Reference ref : instr.getReferencesFrom()) {
        Address toAddr = ref.getToAddress();
        if (toAddr == null) continue;

        MemoryBlock block = mem.getBlock(toAddr);
        if (block == null || !block.getName().equals(".bss")) continue;

        Symbol sym = symTab.getPrimarySymbol(toAddr);
        if (sym == null || sym.getSymbolType() != SymbolType.LABEL) continue;

        setLabelAt(toAddr, className, "instance");
      }
    }
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

  public static void setLabelAt(Address addr, String namespace, String name) {
    try {
      if (namespace != null) { 
        Namespace ns = getOrCreateNamespace(namespace);
        symTab.createLabel(addr, name, ns, SourceType.USER_DEFINED);
      }
      else {
        symTab.createLabel(addr, name, SourceType.USER_DEFINED);
      } 
    }
    catch (InvalidInputException e) {
      error("InvalidInputException", e);
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

  public static void setReturnType(Function func, DataType dt) {
    try {
      func.setReturnType(dt, SourceType.USER_DEFINED);
    }
    catch (InvalidInputException e) {
      error("InvalidInput", e);
    }
  }
}
