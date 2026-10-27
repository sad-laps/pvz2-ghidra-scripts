package com.sad.pvz2.util;

import static com.sad.pvz2.ScriptLogger.error;

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;

public class StructUtil {
  public static void resize(DataTypeManager dtm, StructureDataType struct, int newLength) {
    if (struct.getLength() >= newLength) return;

    struct.setLength(newLength);
    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
  }

  public static StructureDataType getOrCreateStructure(DataTypeManager dtm, CategoryPath path, String name, StructBuilder builder) {
    StructureDataType struct = new StructureDataType(path, name, 0);

    DataType existing = dtm.getDataType(path, name);

    if (existing instanceof StructureDataType dataType)
      return dataType;

    try {
      if (builder != null) builder.accept(struct);
    }
    catch (Exception e) {
      error("Failed to build structure: " + name, e);
    }

    // Add or replace the structure in the DTM cleanly using REPLACE_HANDLER
    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    return struct;
  }

  @FunctionalInterface
  public interface StructBuilder {
    void accept(StructureDataType struct) throws Exception;
  }
}
