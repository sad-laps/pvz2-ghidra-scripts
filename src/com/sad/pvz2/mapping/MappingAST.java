package com.sad.pvz2.mapping;

import java.util.ArrayList;
import java.util.List;

public class MappingAST {
  public record MappingFile(
    List<ClassDef> classes,
    List<FuncDef> sfuncs,
    List<VarDef> svars,
    List<PtrDef> ptrs
  ) {
    public ClassDef getOrAddClass(String name, String size) {
      for (ClassDef c : classes) {
        if (!c.name.equals(name)) continue;

        // Update size if it's wildcard (might make a helper function for updating wildcarded values later or)
        boolean isSizeEmpty = (c.size == null || c.size.equals(MappingUtil.WILDCARD));
        boolean isNewSizeEmpty = (size == null || !size.equals(MappingUtil.WILDCARD));
        if (isSizeEmpty && isNewSizeEmpty) c.size = size;

        return c;
      }

      ClassDef newClass = new ClassDef(name, size, null, null, null, null);
      classes.add(newClass);
      return newClass;
    }

    public String serialize() {
      StringBuilder sb = new StringBuilder();

      // Global Pointers
      if (ptrs() != null)
        for (var ptr : ptrs()) sb.append(ptr);

      // Global Variables
      if (svars() != null)
        for (var varDef : svars()) sb.append(varDef.toString("S", 0));

      // Global Functions
      if (sfuncs() != null)
        for (var func : sfuncs()) sb.append(func.toString("S", 0));

      // Classes
      if (classes() != null)
        for (var cls : classes()) sb.append(cls + "\n");

      return sb.toString();
    }
  }

  // Structure & Class Definitions
  public static class ClassDef {
    public String name, size;
    public VTableDef vtable;
    public List<VarDef> vars;
    public List<FieldDef> fields;
    public List<FuncDef> funcs;

    public ClassDef(String name, String size, VTableDef vtable, List<VarDef> vars, List<FieldDef> fields, List<FuncDef> funcs) {
      this.name = name;
      this.size = size;
      this.vtable = vtable;
      this.vars = vars != null ? vars : new ArrayList<>();
      this.fields = fields != null ? fields : new ArrayList<>();
      this.funcs = funcs != null ? funcs : new ArrayList<>();
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();

      sb.append("CLASS " + name + " " + size + "\n");
      for (var field : fields) sb.append(field.toString(2)); // Fields
      for (var varDef : vars) sb.append(varDef.toString("", 2)); // Class-level Variables
      if (vtable != null) sb.append(vtable.toString(2)); // VTable
      for (var func : funcs) sb.append(func.toString("", 2)); // Class Functions

      return sb.toString();
    }
  }
  public static class FuncDef {
    public String offset, returnType, name;
    public List<ParamDef> params;
    public List<LocalDef> locals;

    public FuncDef(String offset, String returnType, String name, List<ParamDef> params, List<LocalDef> locals) {
      this.offset = offset;
      this.returnType = returnType;
      this.name = name;
      this.params = params != null ? params : new ArrayList<>();
      this.locals = locals != null ? locals : new ArrayList<>();
    }

    public String toString(String prefix, int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + prefix + "FUNC " + offset + " " + returnType + " " + name + "\n");
      for (var param : params) sb.append(" ".repeat(layer + 2) + param);
      for (var local : locals) sb.append(" ".repeat(layer + 2) + local);

      return sb.toString();
    }
  }
  public static class VarDef {
    public String offset, type, name;

    public VarDef(String offset, String type, String name) {
      this.offset = offset;
      this.type = type;
      this.name = name;
    }

    public String toString(String prefix, int layer) {
      return " ".repeat(layer) + prefix + "VAR " + offset + " " + type + " " + name + "\n";
    }
  }
  public static class PtrDef {
    public String offset, type;

    public PtrDef(String offset, String type) {
      this.offset = offset;
      this.type = type;
    }

    @Override
    public String toString() {
      return "PTR " + offset + " " + type + "\n";
    }
  }

  // Class Context
  public static class VTableDef {
    public String offset, superVTable, name, size;
    public List<VFuncDef> funcs;

    public VTableDef(String offset, String superVTable, String name, String size, List<VFuncDef> funcs) {
      this.offset = offset;
      this.superVTable = superVTable;
      this.name = name;
      this.size = size;
      this.funcs = funcs != null ? funcs : new ArrayList<>();
    }

    public String toString(int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + "VTABLE " + offset + " " + superVTable + " " + name + " " + size + "\n");
      for (var vfunc : funcs) sb.append(vfunc.toString(layer + 2));

      return sb.toString();
    }
  }
  public static class VFuncDef {
    public int index;
    public FuncDef funcDef;

    public VFuncDef(int index, FuncDef funcDef) {
      this.index = index;
      this.funcDef = funcDef;
    }

    public String toString(int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + "VFUNC " + index + " " + funcDef.offset + " " + funcDef.returnType + " " + funcDef.name + "\n");
      for (var param : funcDef.params) sb.append(" ".repeat(layer + 2) + param);
      for (var local : funcDef.locals) sb.append(" ".repeat(layer + 2) + local);

      return sb.toString();
    }
  }
  public static class FieldDef {
    public String startOffset, type, name;

    public FieldDef(String startOffset, String type, String name) {
      this.startOffset = startOffset;
      this.type = type;
      this.name = name;
    }

    public String toString(int layer) {
      return " ".repeat(layer) + "FIELD " + startOffset + " " + type + " " + name + "\n";
    }
  }

  // Function Context
  public static class ParamDef {
    public int index;
    public String type, name;

    public ParamDef(int index, String type, String name) {
      this.index = index;
      this.type = type;
      this.name = name;
    }

    @Override
    public String toString() {
      return "PARAM " + index + " " + type + " " + name + "\n";
    }
  }
  public static class LocalDef {
    public String oldName, type, newName;

    public LocalDef(String oldName, String type, String newName) {
      this.oldName = oldName;
      this.type = type;
      this.newName = newName;
    }

    @Override
    public String toString() {
      return "LOCAL " + oldName + " " + type + " " + newName + "\n";
    }
  }
}