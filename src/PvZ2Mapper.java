//Ghidra Script for automatically mapping VTables, functions and other important information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.util.ItaniumUtil;
import com.sad.pvz2.util.ItaniumUtil.ClassNameInfo;
import com.sad.pvz2.util.StructUtil;

import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

public class PvZ2Mapper extends PvZ2BaseScript {
  // Itanium C++ ABI Data Types
  public static StructureDataType typeInfo;
  public static StructureDataType classTypeInfo;
  public static StructureDataType siClassTypeInfo;
  public static StructureDataType baseClassTypeInfo;
  public static StructureDataType vmiClassTypeInfo;

  public static String[] ITANIUM_SYMBOLS = {
    "_ZTVN10__cxxabiv117__class_type_infoE",
    "_ZTVN10__cxxabiv120__si_class_type_infoE",
    "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
  };

  public void run() {
    init("1.0.0", "/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
    logHeader("PvZ2 Mapper", VERSION);

    // Create the Itanium C++ ABI structures beforehand
    initItaniumABIStructures();

    // Analyze te
    analyzeRTTI();
  }

  /**
   * Creates the Itanium C++ ABI structures.
   */
  public static Boolean initializedItanium = false;
  public static void initItaniumABIStructures() {
    CategoryPath rttiPath = new CategoryPath("/_ItaniumABI");

    if (dtm.getDataType(rttiPath, "type_info") == null) initializedItanium = false;

    PointerTypedef offsetRttiPtr = new PointerTypedef("pointer_offset+0x10", UNDEFINED_POINTER_TYPE, 8, dtm, 16);
    // std::type_info (Type Info)
    typeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "type_info", b -> {
      b.add(offsetRttiPtr, 8, "__vptr_type_info", "");
      b.add(new PointerDataType(CharDataType.dataType), 8, "__type_name", "");
    });

    // __class_type_info (Class Type Info)
    classTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__class_type_info", b -> b.add(typeInfo, typeInfo.getLength(), "type_info", ""));

    // __si_class_type_info (Single Inheritance Class Type Info)
    siClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__si_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
    });

    // __base_class_type_info (Base Class Type Info (for vmi))
    baseClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__base_class_type_info", b -> {
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
      // baseClassTypeInfo.add(LongDataType.dataType, 8, "__offset_flags", "");
      // Use `longlong` because Ghidra forces the `long` bitfields to 0x4 size in scripts bruh
      b.addBitField(LongLongDataType.dataType, 4, "__virtual", "");
      b.addBitField(LongLongDataType.dataType, 4, "__public", "");
      b.addBitField(LongLongDataType.dataType, 48, "__offset", "");
    });

    // TODO: Will have to create for each base dynamically  when needed later on!!
    // __vmi_class_type_info (Virtual and Multiple Inheritance Class Type Info)
    vmiClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__vmi_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      b.add(new ArrayDataType(baseClassTypeInfo, 1, baseClassTypeInfo.getLength()), "__base_info", "");
    });

    if (!initializedItanium) log(" * Initialized Itanium C++ ABI structures.");
    initializedItanium = true;
  }

  /**
   * Analyze the Itanium ABI symbols in the binary and use references to map VTables
   */
  public static void analyzeRTTI() {
    for (String symName : ITANIUM_SYMBOLS) {
      List<Symbol> symbols = sytab.getGlobalSymbols(symName);
      for (Symbol sym : symbols)
        analyzeVTablesFromRTTI(sym);
    }
  }

  public static void analyzeVTablesFromRTTI(Symbol sym) {
    ReferenceIterator refs = refman.getReferencesTo(sym.getAddress());

    switch (sym.getName()) {
      case "_ZTVN10__cxxabiv117__class_type_infoE":
        changeDataType(sym.getAddress(), new PointerDataType(classTypeInfo));
        divider();
        log("[INFO] Analyzing Base Classes VTables");
        divider();
        while (refs.hasNext()) analyzeBaseClassRTTI(refs.next().getFromAddress());
        break;
      case "_ZTVN10__cxxabiv120__si_class_type_infoE":
        changeDataType(sym.getAddress(), new PointerDataType(siClassTypeInfo));
        divider();
        log("[INFO] Analyzing Single Inheritance Classes VTables");
        divider();
        while (refs.hasNext()) analyzeSIVTableRTTI(refs.next());
        break;
      case "_ZTVN10__cxxabiv121__vmi_class_type_infoE":
        changeDataType(sym.getAddress(), new PointerDataType(vmiClassTypeInfo));
        divider();
        log("[INFO] Analyzing Virtual Multiple Inheritance Classes VTables");
        divider();
        break;
      default:
        break;
    }
    ID = 0;
  }

  // TODO: REMOVE THIS AFTER TESTING
  public static int ID = 0;
  public static void analyzeBaseClassRTTI(Address typeInfoAddr) {
    ID++; if (ID > 1) return;
    log(" > Analyzing Base Class at 0x" + typeInfoAddr);

    changeDataType(typeInfoAddr, classTypeInfo);

    Data typeInfoData = listing.getDataAt(typeInfoAddr);

    // Get the reference from the `__type_name` inside the `type_info` inside the `__class_type_info`
    Data namePtrData = listing.getDataAt((Address) typeInfoData.getComponent(0).getComponent(1).getValue());
    ClassNameInfo className = ItaniumUtil.demangleItaniumString(getStringFromData(namePtrData));
    log("  * Class Name       : \"" + className.getFullName() + '"');
    if (className.getFullName().contains("$_")) return;

    setLabel(typeInfoAddr, className.getFullName() + "::type_info");
    
    Address rttiPtr = findRTTIPointer(typeInfoAddr);
    //if (rttiPtr == null) return; // TODO: Try fix this somehow since for some reason some type infos dont find the pointer?
    changeDataType(rttiPtr, UNDEFINED_POINTER_TYPE);

    Address vtablePtr = rttiPtr.add(PTR_SIZE);
    // TODO: Check if this is caused by inheritance and don't warn if so
    Boolean isAddress = listing.getDataAt(vtablePtr).getValue() instanceof Address;
    if (!isAddress) { //vtablePtr.equals(typeInfoAddr)
      warn("VTable doesn't reference a valid address!");
      return;
    }

    long vtableSize = typeInfoAddr.subtract(vtablePtr);
    analyzeVTable(vtablePtr, className, vtableSize);
  }

  public static void analyzeSIVTableRTTI(Reference ref) {
    ID++; if (ID > 1) return;
    log("Analyzing Single Inheritance Class from 0x" + ref.getFromAddress());
  }

  public static void analyzeVTable(Address addr, ClassNameInfo className, long size) {
    log("  * VTable Address   : " + addr);
    
    StructureDataType vtableType = generateVTableStruct(className, size);
    changeDataType(addr, vtableType);
    setLabel(addr, className.getFullName() + "VTable");
    
    StructureDataType classType = generateClassStruct(className, vtableType);
    
    // Iterate through the components (function pointers) of the VTable and analyze them
    if (size == 0) return;
    Data vtableData = listing.getDataAt(addr);
    
    log("  * Mapped Functions :");
    int numPointers = (int) (size / PTR_SIZE);
    for (int i = 0; i < numPointers; i++) {
      Data component = vtableData.getComponent(i);
      if (component == null) continue;

      Object val = component.getValue();
      if (val instanceof Address funcAddr) analyzeVTableFunction(i, funcAddr, classType, className);
    }
  }

  public static void analyzeVTableFunction(int i, Address funcAddr, StructureDataType classType, ClassNameInfo className) {
    Function func = listing.getFunctionAt(funcAddr);
    if (func == null) return;
    try {
      func.setName(className.getFullName() + "::func" + i, SourceType.USER_DEFINED);
    }
    catch (Exception e) {
      error("Could not update function at 0x" + funcAddr, e);
    }

    String funcName = func.getName();

    DecompileResults res = decomp.decompileFunction(func, 30, null);
    try {
      // Sets the parameters and return type correctly
      if (!res.decompileCompleted()) return;
      HighFunction highFunc = res.getHighFunction();
      if (highFunc == null) return;
      HighFunctionDBUtil.commitParamsToDatabase(highFunc, true, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED);

      // Set the first parameter name to `self` as it's always a pointer to the Object itself
      func.getParameter(0).setName("self", SourceType.USER_DEFINED);
      func.getParameter(0).setDataType(new PointerDataType(classType), SourceType.USER_DEFINED);

      // Try check for destroyer function to set the real class struct size
      long detectedSize = extractClassSizeFromPcode(highFunc);
      if (detectedSize > 0 && classType.getLength() < detectedSize) {
        log("   + Detected Size   : " + detectedSize + " bytes (0x" + Long.toHexString(detectedSize) + ")");
        StructUtil.resize(dtm, classType, (int) detectedSize);
      }
    }
    catch (Exception e) {
      error("Could not update function at 0x" + funcAddr, e);
    }
    log("  [" + i + "] 0x" + funcAddr + " -> " + funcName);
  }

  public static long extractClassSizeFromPcode(HighFunction highFunc) {
    Varnode selfVarnode = new Varnode(highFunc.getFunction().getParameter(0).getMinAddress(), highFunc.getFunction().getParameter(0).getLength());

    Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
    while (ops.hasNext()) {
      PcodeOp op = ops.next();

      if (op.getOpcode() != PcodeOp.CALL) continue;
      if (op.getNumInputs() < 3) continue;
      
      Varnode target = op.getInput(0);
      if (target == null || target.getAddress() == null) continue;

      Function calledFunc = listing.getFunctionAt(target.getAddress());
      if (calledFunc == null) continue;

      if (!calledFunc.getName().contains("delete")) continue;
      
      Varnode ptrArg = op.getInput(1);
      if (ptrArg == null) continue;

      boolean isDeletingSelf = ptrArg.getOffset() == selfVarnode.getOffset();
      if (!isDeletingSelf) continue;

      Varnode sizeArg = op.getInput(2);
      if (sizeArg == null) continue;

      long val = sizeArg.getOffset();
      if (val >= 8 && val <= 4096 && (val % 4 == 0)) return val;
    }
    return -1;
  }

  public static StructureDataType generateVTableStruct(ClassNameInfo className, long size) {
    StructureDataType struct = new StructureDataType(className.toCategoryPath(PVZ2_CATEGORY), className.name() + "VTable", 0);

    // TODO: Will have to handle this differently, I could use the types given from the functions when I analyze them better, so do this after analyzing the functions best!
    int numPointers = (int) (size / PTR_SIZE);
    for (int i = 0; i < numPointers; i++) {
      struct.add(UNDEFINED_POINTER_TYPE, PTR_SIZE, "func_" + i, "");
    }

    dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
    return struct;
  }

  public static StructureDataType generateClassStruct(ClassNameInfo className, StructureDataType vtableType) {
    StructureDataType struct = new StructureDataType(className.toCategoryPath(PVZ2_CATEGORY), className.name(), 0);

    // TODO: Will have to handle this differently, I could use the set parameters in the destroy functions or super classes when I analyze them better, so do this after analyzing the functions best?
    struct.add(new PointerDataType(vtableType), PTR_SIZE, "vtable", "");

    dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
    return struct;
  }

  public static Address findRTTIPointer(Address typeInfoAddr) {
    long targetValue = typeInfoAddr.getOffset();
    Address curr = typeInfoAddr.subtract(PTR_SIZE);

    for (int i = 0; i < 64; i++) {
      try {
        long val = mem.getLong(curr);
        if (val == targetValue) {
          return curr; // Found 02f7d570!
        }
      } catch (MemoryAccessException e) {
        break;
      }
      curr = curr.subtract(PTR_SIZE);
    }
    return null;
  }

  /**
   * Helper method to create VMI Class Type Info structures with varying sizes
   */
  public StructureDataType getOrCreateVMIStructure(CategoryPath path, int size) {
    if (size == 1) return vmiClassTypeInfo; // vmiClassTypeInfo is already single base

    StructureDataType vmiStruct = StructUtil.getOrCreateStructure(dtm, path, "__vmi_class_type_info_" + size + "bases", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");      
      b.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      b.add(new ArrayDataType(baseClassTypeInfo, size, baseClassTypeInfo.getLength()), "__base_info", "");
    });
    return vmiStruct;
  }

  public static String getStringFromData(Data data) {
    try {
      if (data != null && data.getValue() instanceof String str)
        return str;
    }
    catch (Exception e) {
      error("Could not read string at 0x" + data.getAddress() + ": ", e);
    }
    return "";
  }

  /**
   * Helper method to change data type of an address, returns error if it couldn't change it
   */
  public static void changeDataType(Address addr, DataType newType) {
    // If it's already the exact same type, skip re-applying it!
    Data existingData = listing.getDataAt(addr);
    if (existingData != null) {
      DataType currentType = existingData.getDataType();
      if (currentType.isEquivalent(newType)) return;
    }
    
    try {
      int length = newType.getLength();
      if (length > 0) {
        listing.clearCodeUnits(addr, addr.add(length - 1), false);
      }
      listing.createData(addr, newType);
      log("  [0x" + addr + "] Type assigned >> " + newType.getName());
    }
    catch (Exception e) {
      error("Could not change type to " + newType.getName() + " at 0x" + addr + ": ", e);
    }
  }

  public static void setLabel(Address addr, String name) {
    try {
      sytab.createLabel(addr, name, SourceType.USER_DEFINED);
    }
    catch (InvalidInputException e) {
      error("Could not create label '" + name + "' at 0x" + addr, e);
    }
  }
}