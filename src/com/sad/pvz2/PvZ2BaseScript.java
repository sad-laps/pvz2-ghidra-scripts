package com.sad.pvz2;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolTable;

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
}
