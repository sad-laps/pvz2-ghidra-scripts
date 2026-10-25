package com.sad.pvz2;

import static com.sad.pvz2.ScriptLogger.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

public abstract class PvZ2BaseScript extends GhidraScript {
  public static String VERSION;

  public static final int PTR_SIZE = 8;

  public static PointerDataType UNDEFINED_POINTER_TYPE = new PointerDataType(DataType.DEFAULT); // undefined *

  public static final CategoryPath PVZ2_CATEGORY = new CategoryPath("/_PvZ2Classes");

  protected static DecompInterface decomp = new DecompInterface();

  protected static Program program;
  protected static DataTypeManager dtm;
  protected static SymbolTable sytab;
  protected static ReferenceManager refman;
  protected static Listing listing;
  protected static Memory mem;

  protected void init(String version, String logPath, String logFileName) {
    ScriptLogger.init(this, logPath, logFileName);
    VERSION = version;
    program = currentProgram;
    dtm = currentProgram.getDataTypeManager();
    sytab = currentProgram.getSymbolTable();
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
      log("  [0x" + addr + "] Type assigned >> " + newType.getName());
    }
    catch (Exception e) {
      error("Could not change type to " + newType.getName() + " at 0x" + addr + ": ", e);
    }
  }
  
  public static void setLabel(Address addr, String namespaceStr, String labelName) {
    log(" * Creating label: " + namespaceStr + labelName);
    try {
      Namespace nspc = getOrCreateNamespace(namespaceStr);
      sytab.createLabel(addr, labelName, nspc, SourceType.USER_DEFINED);
    }
    catch (InvalidInputException e) {
      error("Could not create label '" + namespaceStr + "::" + labelName + "' at 0x" + addr, e);
    }
  }

  public static Namespace getOrCreateNamespace(String namespacePath) {
    Namespace ns = program.getGlobalNamespace();
    if (namespacePath == null || namespacePath.isEmpty()) return ns;

    String[] parts = namespacePath.split("::");
    for (String nsPart : parts) {
      if (nsPart.isEmpty()) continue;

      Namespace sub = sytab.getNamespace(nsPart, ns);
      if (sub == null) {
        try {
          sub = sytab.createNameSpace(ns, nsPart, SourceType.USER_DEFINED);
          log(" * Create namespace at '" + namespacePath + "'");
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
