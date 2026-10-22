//Ghidra Script for automatically mapping VTables, functions and other important information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import com.sad.pvz2.ScriptLogger;
import static com.sad.pvz2.ScriptLogger.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class PvZ2Mapper extends GhidraScript {
  public static int PTR_SIZE = 8;
  public static PointerDataType UNDEFINED_POINTER_TYPE = new PointerDataType(DataType.DEFAULT); // undefined *
  public int i = 0;

  public DataTypeManager dtm;
  public StructureDataType typeInfo;
  public StructureDataType classTypeInfo;
  public StructureDataType siClassTypeInfo;
  public StructureDataType baseClassTypeInfo;
  public StructureDataType vmiClassTypeInfo;
  
  public CategoryPath pvz2Category;

  public Address currentVTable;

  public void run() {
    ScriptLogger.init(this, "/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
    dtm = currentProgram.getDataTypeManager();
    logHeader("PvZ2 Mapper");

    // Analyse .data.rel.ro addresses
    MemoryBlock block = currentProgram.getMemory().getBlock(".data.rel.ro");
    Address currAddr = block.getStart();

    // Create the Itanium C++ ABI structures beforehand
    initItaniumABIStructures();

    pvz2Category = new CategoryPath("/_PvZ2Classes");

    for (; i < 10; i++) { // block.getSize() / PTR_SIZE
      if (currAddr.compareTo(block.getEnd()) > 0) {
        log("Reached the end of the memory block early.");
        break;
      }
      analyseVTableAddr(currAddr);
      currAddr = currAddr.add(PTR_SIZE);
    }
  }

  /**
   * Creates the Itanium C++ ABI structures.
   */
  public void initItaniumABIStructures() {
    CategoryPath rttiPath = new CategoryPath("/_ItaniumABI");

    PointerTypedef offsetRttiPtr = new PointerTypedef("pointer_offset+0x10", UNDEFINED_POINTER_TYPE, 8, dtm, 16);
    // std::type_info (Type Info)
    typeInfo = getOrCreateStructure(rttiPath, "type_info");
    if (typeInfo.getNumComponents() == 0) {
      typeInfo.add(offsetRttiPtr, 8, "__vptr_type_info", "");
      typeInfo.add(new PointerDataType(CharDataType.dataType), 8, "__type_name", "");
    }

    // __class_type_info (Class Type Info)
    classTypeInfo = getOrCreateStructure(rttiPath, "__class_type_info");
    if (classTypeInfo.getNumComponents() == 0) {
      classTypeInfo.add(typeInfo, typeInfo.getLength(), "type_info", "");
    }

    // __si_class_type_info (Single Inheritance Class Type Info)
    siClassTypeInfo = getOrCreateStructure(rttiPath, "__si_class_type_info");
    if (siClassTypeInfo.getNumComponents() == 0) {
      siClassTypeInfo.add(typeInfo, typeInfo.getLength(), "type_info", "");
      siClassTypeInfo.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
    }

    try {
      // __base_class_type_info (Base Class Type Info (for vmi))
      baseClassTypeInfo = getOrCreateStructure(rttiPath, "__base_class_type_info");
      if (baseClassTypeInfo.getNumComponents() == 0) {
        baseClassTypeInfo.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
        // baseClassTypeInfo.add(LongDataType.dataType, 8, "__offset_flags", "");
        // Use `longlong` because Ghidra forces the `long` bitfields to 0x4 size in scripts bruh
        baseClassTypeInfo.addBitField(LongLongDataType.dataType, 4, "__virtual", "");
        baseClassTypeInfo.addBitField(LongLongDataType.dataType, 4, "__public", "");
        baseClassTypeInfo.addBitField(LongLongDataType.dataType, 48, "__offset", "");
      }
    }
    catch (InvalidDataTypeException e) {
      error("InvalidDataTypeException when creating __base_class_type_info", e);
    }

    // TODO: Will have to create for each base dynamically  when needed later on!!
    // __vmi_class_type_info (Virtual and Multiple Inheritance Class Type Info)
    vmiClassTypeInfo = getOrCreateStructure(rttiPath, "__vmi_class_type_info");
    if (vmiClassTypeInfo.getNumComponents() == 0) {
      vmiClassTypeInfo.add(typeInfo, typeInfo.getLength(), "type_info", "");
      vmiClassTypeInfo.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");
      vmiClassTypeInfo.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      vmiClassTypeInfo.add(new ArrayDataType(baseClassTypeInfo, 1, baseClassTypeInfo.getLength()), "__base_info", "");
    }

    log(" * Initialized Itanium C++ ABI structures.");
  }

  /**
   * Helper method to analyse VTable addresses
   */
  public void analyseVTableAddr(Address addr) {
    Listing listing = currentProgram.getListing();
    Memory mem = currentProgram.getMemory();

    Data data = listing.getDataAt(addr);
    if (data == null) return;

    // Skip if the type is already a qword
    if (data != null && data.getDataType() instanceof QWordDataType) return;

    String typeName = (data != null) ? data.getDataType().getName() : "Unknown Type";

    long rawValue = 0;
    Address targetAddr = null;
    try {
      rawValue = mem.getLong(addr);
      targetAddr = toAddr(rawValue);
    }
    catch (MemoryAccessException e) {
      error("MemoryAccessException", e);
    }

    // Check if address is in the binary memory block, if not make it a qword for cleaning the code
    MemoryBlock targetBlock = null;
    if (targetAddr != null && mem.contains(targetAddr)) {
      targetBlock = mem.getBlock(targetAddr);
    }

    // TODO: Will have to handle patterns such as non-0 byte paddings
    // since some have `FFFFFFFFFFFFFDE0h` or `FFFFFFFFFFFFFFF8h` which can be metadata for vtables themselves ?
    // there's also `0000000000001002h` or `0000000000001802h` under the .rodata symbol metadata for super classes?
    if (targetBlock == null) {
      changeDataType(addr, QWordDataType.dataType);
      return;
    }

    Symbol targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(targetAddr);

    // Check if address targets a symbol such as pointers or functions, if not make it a pointer
    if (targetSymbol == null || typeName == "undefined") {
      changeDataType(addr, UNDEFINED_POINTER_TYPE);
      targetSymbol = currentProgram.getSymbolTable().getPrimarySymbol(targetAddr);
    }

    data = listing.getDataAt(addr);
    typeName = (data != null) ? data.getDataType().getName() : "Unknown Type";
    String targetName = (targetSymbol != null) ? targetSymbol.getName() : "Unlabeled Function/Data";

    // Check if the target is from .rodata and create Class+VTable structures for it
    if (targetBlock.getName().equals(".rodata")) {
      String str = getStringFromType(targetAddr);
      if (!str.isEmpty()) createClassStructures(str, addr);
    }

    log("[" + i + "] Analysing Address: 0x" + addr + " | Type: " + typeName + " | Label: " + data.getLabel() + " | Target Symbol: " + targetName);

    // Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(addr);
  }

  public void createClassStructures(String rawClassName, Address sourceAddr) {
    String className = rawClassName.replaceAll("^\\d+", "");
    

    // StructureDataType objStruct = new StructureDataType(pvz2Category, className, 0);
    // objStruct.add(new PointerDataType(DataType.DEFAULT), 8, "vtable", "");

    // StructureDataType vtableStruct = new StructureDataType(categoryPath, className + "VTable", 0);
    
    // dtm.addDataType(objStruct, DataTypeConflictHandler.REPLACE_HANDLER);
    // dtm.addDataType(vtableStruct, DataTypeConflictHandler.REPLACE_HANDLER);
    // log(" * Created Namespace & Structures under " + categoryPath.getPath());
  }

  /**
   * Helper method to create VMI Class Type Info structures with varying sizes
   */
  public StructureDataType getOrCreateVMIStructure(CategoryPath path, int size) {
    if (size == 1) return vmiClassTypeInfo; // vmiClassTypeInfo is already single base

    StructureDataType vmiStruct = getOrCreateStructure(path, "__vmi_class_type_info_" + size + "bases");
    if (vmiStruct.getNumComponents() == 0) {
      vmiStruct.add(typeInfo, typeInfo.getLength(), "type_info", "");
      vmiStruct.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");
      vmiStruct.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      vmiStruct.add(new ArrayDataType(baseClassTypeInfo, size, baseClassTypeInfo.getLength()), "__base_info", "");
    }
    return vmiStruct;
  }

  public StructureDataType getOrCreateStructure(CategoryPath path, String name) {
    DataType existing = dtm.getDataType(path, name);

    if (existing instanceof StructureDataType dataType)
      return dataType;

    StructureDataType newStruct = new StructureDataType(path, name, 0);
    dtm.addDataType(newStruct, DataTypeConflictHandler.DEFAULT_HANDLER);
    return newStruct;
  }

  public String getStringFromType(Address addr) {
    Listing listing = currentProgram.getListing();
    Data data = listing.getDataAt(addr);

    try {
      if (data != null && data.getValue() instanceof String str)
        return str;
    }
    catch (Exception e) {
      error("Could not read string at 0x" + addr + ": ", e);
    }
    return "";
  }

  /**
   * Helper method to change data type of an address, returns error if it couldn't change it
   */
  public void changeDataType(Address addr, DataType newType) {
    Listing listing = currentProgram.getListing();

    try {
      listing.clearCodeUnits(addr, addr.add(PTR_SIZE - 1), false);
      listing.createData(addr, newType);
      log("[" + i + "] Changed Address: 0x" + addr + " to Type: " + newType.getName());
    }
    catch (Exception e) {
      error("Could not create " + newType.getName() + " at 0x" + addr + ": ", e);
    }

    return;
  }
}