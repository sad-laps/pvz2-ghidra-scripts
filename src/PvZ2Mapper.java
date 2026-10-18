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
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;

public class PvZ2Mapper extends GhidraScript {
  private int PTR_SIZE = 8;
  private Path logPath = Paths.get("/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");

  public void run() throws Exception {
    MemoryBlock block = currentProgram.getMemory().getBlock(".data.rel.ro");

    Address currAddr = block.getStart();

    // Write log Header
    log("\n============================================", false);
    log("| PvZ2 Mapper Log from " + DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()) + " |", false);
    log("============================================\n", false);

    // Analyse addresses
    // block.getSize() / PTR_SIZE
    for (int i = 0; i < 10; i++) {
      if (currAddr.compareTo(block.getEnd()) > 0) {
        log("Reached the end of the memory block early.");
        break;
      }
      analyseVTableAddr(i, currAddr);
      currAddr = currAddr.add(PTR_SIZE);
    }
  }

  /**
   * Helper method to analyse VTable addresses
   */
  public void analyseVTableAddr(int i, Address addr) throws Exception {
    log("Analyzing address [" + i + "] 0x" + addr);

    Data data = currentProgram.getListing().getDataAt(addr);
    Reference[] refs = currentProgram.getReferenceManager().getReferencesFrom(addr);
    long rawValue = currentProgram.getMemory().getLong(addr);
    Address targetAddr = toAddr(rawValue);
  }

  /**
   * Helper method to write text in Ghidra Console and log file
   */
  public void log(String message, boolean inConsole) {
    if (inConsole) println(message);

    // Write to log file
    try {
      if (logPath.getParent() != null) {
        Files.createDirectories(logPath.getParent());
      }
      Files.writeString(logPath, message + System.lineSeparator(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
    catch (IOException e) {
      printerr("Failed to write to log file: " + e.getMessage());
    }
  }

  public void log(String message) {
    log(message, true);
  }
}