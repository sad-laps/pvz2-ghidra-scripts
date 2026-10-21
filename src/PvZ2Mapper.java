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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.StructureDataType;
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

  public void run() {
    ScriptLogger.init(this, "/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
    logHeader("PvZ2 Mapper");

    // Analyse .data.rel.ro addresses
    MemoryBlock block = currentProgram.getMemory().getBlock(".data.rel.ro");
    Address currAddr = block.getStart();

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
    DataTypeManager dtm = currentProgram.getDataTypeManager();

    CategoryPath categoryPath = new CategoryPath("/_PvZ2Classes/" + className);
    
    StructureDataType objStruct = new StructureDataType(categoryPath, className, 0);
    objStruct.add(new PointerDataType(DataType.DEFAULT), 8, "vtable", "");

    StructureDataType vtableStruct = new StructureDataType(categoryPath, className + "VTable", 0);
    
    dtm.addDataType(objStruct, DataTypeConflictHandler.REPLACE_HANDLER);
    dtm.addDataType(vtableStruct, DataTypeConflictHandler.REPLACE_HANDLER);
    log(" * Created Namespace & Structures under " + categoryPath.getPath());
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