//Ghidra Script for automatically mapping VTables, functions and other important information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import com.sad.pvz2.ScriptLogger;
import static com.sad.pvz2.ScriptLogger.*;

import java.util.List;

import javax.help.Map.ID;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class PvZ2Mapper extends GhidraScript {
  public static int PTR_SIZE = 8;
  public static PointerDataType UNDEFINED_POINTER_TYPE = new PointerDataType(DataType.DEFAULT); // undefined *

  public static DataTypeManager dtm;
  public static SymbolTable sytab;
  public static ReferenceManager refman;
  public static Listing listing;
  public static CategoryPath pvz2Category;

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
    ScriptLogger.init(this, "/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
    dtm = currentProgram.getDataTypeManager();
    sytab = currentProgram.getSymbolTable();
    refman = currentProgram.getReferenceManager();
    listing = currentProgram.getListing();

    logHeader("PvZ2 Mapper");

    // Create the Itanium C++ ABI structures beforehand
    initItaniumABIStructures();

    pvz2Category = new CategoryPath("/_PvZ2Classes");

    // Analyze te
    analyzeRTTI();

    log("\n============================================\n", false);
  }

  /**
   * Creates the Itanium C++ ABI structures.
   */
  public static void initItaniumABIStructures() {
    CategoryPath rttiPath = new CategoryPath("/_ItaniumABI");

    PointerTypedef offsetRttiPtr = new PointerTypedef("pointer_offset+0x10", UNDEFINED_POINTER_TYPE, 8, dtm, 16);
    // std::type_info (Type Info)
    typeInfo = getOrCreateStructure(rttiPath, "type_info", b -> {
      b.add(offsetRttiPtr, 8, "__vptr_type_info", "");
      b.add(new PointerDataType(CharDataType.dataType), 8, "__type_name", "");
    });

    // __class_type_info (Class Type Info)
    classTypeInfo = getOrCreateStructure(rttiPath, "__class_type_info", b -> b.add(typeInfo, typeInfo.getLength(), "type_info", ""));

    // __si_class_type_info (Single Inheritance Class Type Info)
    siClassTypeInfo = getOrCreateStructure(rttiPath, "__si_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
    });

    // __base_class_type_info (Base Class Type Info (for vmi))
    baseClassTypeInfo = getOrCreateStructure(rttiPath, "__base_class_type_info", b -> {
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
      // baseClassTypeInfo.add(LongDataType.dataType, 8, "__offset_flags", "");
      // Use `longlong` because Ghidra forces the `long` bitfields to 0x4 size in scripts bruh
      b.addBitField(LongLongDataType.dataType, 4, "__virtual", "");
      b.addBitField(LongLongDataType.dataType, 4, "__public", "");
      b.addBitField(LongLongDataType.dataType, 48, "__offset", "");
    });

    // TODO: Will have to create for each base dynamically  when needed later on!!
    // __vmi_class_type_info (Virtual and Multiple Inheritance Class Type Info)
    vmiClassTypeInfo = getOrCreateStructure(rttiPath, "__vmi_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      b.add(new ArrayDataType(baseClassTypeInfo, 1, baseClassTypeInfo.getLength()), "__base_info", "");
    });

    log(" * Initialized Itanium C++ ABI structures.");
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
        log("--- Analyzing Base Classes VTables ---");
        while (refs.hasNext()) analyzeBaseVTableRTTI(refs.next().getFromAddress());
        break;
      case "_ZTVN10__cxxabiv120__si_class_type_infoE":
        changeDataType(sym.getAddress(), new PointerDataType(siClassTypeInfo));
        log("--- Analyzing Single Inheritance Classes VTables ---");
        while (refs.hasNext()) analyzeSIVTableRTTI(refs.next());
        break;
      case "_ZTVN10__cxxabiv121__vmi_class_type_infoE":
        changeDataType(sym.getAddress(), new PointerDataType(vmiClassTypeInfo));
        log("--- Analyzing Virtual Multiple Inheritance Classes VTables ---");
        break;
      default:
        break;
    }
    ID = 0;
  }

  // TODO: REMOVE THIS AFTER TESTING
  public static int ID = 0;
  public static void analyzeBaseVTableRTTI(Address typeInfoAddr) {
    ID++; if (ID > 1) return;
    Data data = listing.getDataAt(typeInfoAddr);
    String typeName = (data != null) ? data.getDataType().getName() : "Unknown Type";
    String className = "";
    log("Analyzing Base Class " + className + " from 0x" + typeInfoAddr + " | Type: " + typeName);
    
    // TODO: Check if it's actually the type name and use it
    changeDataType(typeInfoAddr.add(PTR_SIZE), new PointerDataType(DataType.DEFAULT));
  }

  public static void analyzeSIVTableRTTI(Reference ref) {
    ID++; if (ID > 1) return;
    log("Analyzing Single Inheritance Class from 0x" + ref.getFromAddress());
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

  @FunctionalInterface
  public interface StructBuilder {
    void accept(StructureDataType struct) throws Exception;
  }

  /**
   * Helper method to create VMI Class Type Info structures with varying sizes
   */
  public StructureDataType getOrCreateVMIStructure(CategoryPath path, int size) {
    if (size == 1) return vmiClassTypeInfo; // vmiClassTypeInfo is already single base

    StructureDataType vmiStruct = getOrCreateStructure(path, "__vmi_class_type_info_" + size + "bases", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");      
      b.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      b.add(new ArrayDataType(baseClassTypeInfo, size, baseClassTypeInfo.getLength()), "__base_info", "");
    });
    return vmiStruct;
  }

  public static StructureDataType getOrCreateStructure(CategoryPath path, String name, StructBuilder builder) {
    DataType existing = dtm.getDataType(path, name);

    if (existing instanceof StructureDataType dataType)
      return dataType;

    StructureDataType struct = new StructureDataType(path, name, 0);
    try {
      builder.accept(struct);
    }
    catch (Exception e) {
      error("Failed to build structure: " + name, e);
    }
    dtm.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
    return struct;
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
  public static void changeDataType(Address addr, DataType newType) {
    // If it's already the exact same type, skip re-applying it!
    Data existingData = listing.getDataAt(addr);
    if (existingData != null) {
      DataType currentType = existingData.getDataType();
      if (currentType.isEquivalent(newType)) return;
    }
    
    try {
      listing.clearCodeUnits(addr, addr.add(PTR_SIZE - 1), false);
      listing.createData(addr, newType);
      log(" * Changed address 0x" + addr + " to Type: " + newType.getName());
    }
    catch (Exception e) {
      error("Could not create " + newType.getName() + " at 0x" + addr + ": ", e);
    }
  }
}