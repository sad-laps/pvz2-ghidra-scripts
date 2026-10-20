//Ghidra Script for automatically mapping VTables, functions and other important information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

public class PvZ2Mapper extends GhidraScript {
  private static int PTR_SIZE = 8;
  private static Path LOG_PATH = Paths.get("/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
  public static PointerDataType UNDEFINED_POINTER_TYPE = new PointerDataType(DataType.DEFAULT); // undefined *
  public int i = 0;


  public void run() throws Exception {
    MemoryBlock block = currentProgram.getMemory().getBlock(".data.rel.ro");

    Address currAddr = block.getStart();

    // Write log Header
    log("\n============================================", false);
    log("| PvZ2 Mapper Log from " + DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()) + " |", false);
    log("============================================\n", false);

    // Analyse addresses
    // block.getSize() / PTR_SIZE
    for (; i < 300; i++) {
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
  public void analyseVTableAddr(Address addr) throws Exception {
    Listing listing = currentProgram.getListing();
    Memory mem = currentProgram.getMemory();

    Data data = listing.getDataAt(addr);
    if (data == null) return;

    // Skip if the type is already a qword
    if (data != null && data.getDataType() instanceof QWordDataType) return;

    String typeName = (data != null) ? data.getDataType().getName() : "Unknown Type";

    long rawValue = mem.getLong(addr);
    Address targetAddr = toAddr(rawValue);

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

    log("[" + i + "] Analysing Address: 0x" + addr + " | Type: " + typeName + " | Label: " + data.getLabel() + " | Target Symbol: " + targetName);

    // Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(addr);
  }

  /**
   * Helper methods to change data type of an address, returns error if it couldn't change it
   */
  public void changeDataType(Address addr, DataType newType) {
    Listing listing = currentProgram.getListing();

    try {
      listing.clearCodeUnits(addr, addr.add(PTR_SIZE - 1), false);
      listing.createData(addr, newType);
      log("[" + i + "] Changed Address: 0x" + addr + " to Type: " + newType.getName());
    }
    catch (Exception e) {
      log("  -> [Error] Could not create " + newType.getName() + " at 0x" + addr + ": " + e.getMessage());
    }

    return;
  }

  /**
   * Helper methods to write text in Ghidra Console and in a log file
   */
  public void log(String message, boolean inConsole) {
    if (inConsole) println(message);

    // Write to log file
    try {
      if (LOG_PATH.getParent() != null) {
        Files.createDirectories(LOG_PATH.getParent());
      }
      Files.writeString(LOG_PATH, message + System.lineSeparator(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
    catch (IOException e) {
      printerr("Failed to write to log file: " + e.getMessage());
    }
  }

  public void log(String message) {
    log(message, true);
  }
}