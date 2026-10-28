package com.sad.pvz2;

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

public abstract class PvZ2BaseScript extends GhidraScript {
  public String SCRIPT_VERSION;
  public String GAME_VERSION;

  public static int PTR_SIZE;
  public static PointerDataType UNDEFINED_POINTER_TYPE; // undefined *

  public static final String PVZ2_CATEGORY_PATH = "/_PvZ2Classes";
  public static final CategoryPath PVZ2_CATEGORY = new CategoryPath(PVZ2_CATEGORY_PATH);

  protected static DecompInterface decomp = new DecompInterface();

  protected static Program program;
  protected static AddressFactory addr;
  protected static DataTypeManager dtm;
  protected static SymbolTable symTab;
  protected static ReferenceManager refman;
  protected static Listing listing;
  protected static Memory mem;

  protected static File scriptDir;

  protected void init(String version, String gameVersion, String logFileName) {
    PTR_SIZE = currentProgram.getDefaultPointerSize();
    UNDEFINED_POINTER_TYPE = new PointerDataType(DataType.DEFAULT, PTR_SIZE);

    // TODO: Will have to change this on release to allow user to choose log file name and path!
    File scriptFile = sourceFile.getFile(false);
    scriptDir = scriptFile != null ? scriptFile.getParentFile() : new File(".");
    File logsDir = new File(scriptDir.getParentFile(), "logs");

    ScriptLogger.init(this, logsDir.getPath(), logFileName);

    SCRIPT_VERSION = version;
    GAME_VERSION = gameVersion;
    program = currentProgram;
    addr = currentProgram.getAddressFactory();
    dtm = currentProgram.getDataTypeManager();
    symTab = currentProgram.getSymbolTable();
    refman = currentProgram.getReferenceManager();
    listing = currentProgram.getListing();
    mem = currentProgram.getMemory();

    decomp.openProgram(currentProgram);
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
      log(" [0x" + addr + "] Type assigned >> " + newType.getName());
    }
    catch (Exception e) {
      error("Could not change type to " + newType.getName() + " at 0x" + addr + ": ", e);
    }
  }
  
  public static void setLabel(Address addr, String namespaceStr, String labelName) {
    log(" * Added label: " + namespaceStr + "::" + labelName);
    try {
      Namespace nspc = getOrCreateNamespace(namespaceStr);
      symTab.createLabel(addr, labelName, nspc, SourceType.USER_DEFINED);
    }
    catch (InvalidInputException e) {
      error("Could not create label '" + namespaceStr + "::" + labelName + "' at 0x" + addr, e);
    }
  }

  public static Namespace getOrCreateNamespace(String namespacePath) {
    Namespace ns = program.getGlobalNamespace();
    if (namespacePath == null || namespacePath.isEmpty()) return ns;

    for (String nsPart : namespacePath.split("::")) {
      if (nsPart.isEmpty()) continue;

      Namespace sub = symTab.getNamespace(nsPart, ns);
      if (sub == null) {
        try {
          sub = symTab.createNameSpace(ns, nsPart, SourceType.USER_DEFINED);
          log(" * Added namespace '" + namespacePath + "'");
        }
        catch (Exception e) {
          error("Could not create namespace at '" + namespacePath + "'", e);
        }
      }
      ns = sub;
    }
    return ns;
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
}
