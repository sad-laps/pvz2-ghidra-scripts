package com.sad.pvz2.mapping;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MappingAST {
  public record MappingFile(
    List<ClassDef> classes,
    List<FuncDef> sfuncs,
    List<VarDef> svars,
    List<PtrDef> ptrs
  ) {
    public ClassDef getOrAddClass(String name, String size, List<FieldDef> fields) {
      for (ClassDef c : classes) {
        if (!c.name.equals(name)) continue;

        c.size.update(size);
        if (fields != null && !fields.isEmpty()) c.fields = fields;

        return c;
      }

      ClassDef newClass = new ClassDef(name, size, null, null, fields, null);
      classes.add(newClass);
      return newClass;
    }

    public FuncDef getOrSetSFunc(String offset, String returnType, String name) {
      return FuncDef.getOrSet(sfuncs, offset, returnType, name);
    }

    public VarDef getOrSetSVar(String offset, String type, String name) {
      return VarDef.getOrSet(svars, offset, type, name);
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
    public String name;
    public Wildcardable size;
    public VTableDef vtable;
    public List<VarDef> vars;
    public List<FieldDef> fields;
    public List<FuncDef> funcs;

    public ClassDef(String name, String size, VTableDef vtable, List<VarDef> vars, List<FieldDef> fields, List<FuncDef> funcs) {
      this.name = name;
      this.size = new Wildcardable(size);
      this.vtable = vtable;
      this.vars = vars != null ? vars : new ArrayList<>();
      this.fields = fields != null ? fields : new ArrayList<>();
      this.funcs = funcs != null ? funcs : new ArrayList<>();
    }

    public boolean hasVFuncAtOffset(String offset) {
      if (vtable == null || vtable.funcs == null) return false;
      for (var vf : vtable.funcs) {
        if (vf.funcDef.offset.equalsIgnoreCase(offset)) return true;
      }
      return false;
    }

    public FuncDef getOrSetFunc(String offset, String returnType, String name) {
      return FuncDef.getOrSet(funcs, offset, returnType, name);
    }

    public VarDef getOrSetVar(String offset, String type, String name) {
      return VarDef.getOrSet(vars, offset, type, name);
    }

    public VTableDef getOrSetVTable(String offset, String superVTable, String name, String size) {
      if (this.vtable == null) {
        this.vtable = new VTableDef(offset, superVTable, name, size, null);
      }
      else {
        this.vtable.offset = offset;
        this.vtable.name = name;
        this.vtable.superVTable.update(superVTable);
        this.vtable.size.update(size);
      }
      return this.vtable;
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
    public String offset, returnType;
    public Wildcardable name;
    public List<ParamDef> params;
    public Map<String, LocalDef> locals;

    public FuncDef(String offset, String returnType, String name, List<ParamDef> params, Map<String, LocalDef> locals) {
      this.offset = offset;
      this.returnType = returnType;
      this.name = new Wildcardable(name);
      this.params = params != null ? params : new ArrayList<>();
      this.locals = locals != null ? locals : new HashMap<>();
    }

    public static FuncDef getOrSet(List<FuncDef> list, String offset, String returnType, String name) {
      for (FuncDef f : list) {
        if (f.offset.equalsIgnoreCase(offset)) {
          f.returnType = returnType;
          f.name.update(name);
          return f;
        }
      }
      FuncDef newFunc = new FuncDef(offset, returnType, name, null, null);
      list.add(newFunc);
      return newFunc;
    }

    public ParamDef getOrSetParam(int index, String type, String name) {
      for (ParamDef p : params) {
        if (p.index == index) {
          p.type = type;
          p.name = name;
          return p;
        }
      }
      ParamDef newParam = new ParamDef(index, type, name);
      params.add(newParam);
      return newParam;
    }

    public LocalDef getOrSetLocal(String oldName, String type, String newName) {
      for (LocalDef l : locals.values()) {
        if (l.newName != null && l.newName.equalsIgnoreCase(newName)) {
          if (oldName != null && !oldName.equals(MappingUtil.WILDCARD)) {
            locals.remove(l.oldName);
            l.oldName = oldName;
          }
          l.type = type;
          l.newName = newName;
          locals.put(l.oldName, l);
          return l;
        }
      }

      LocalDef l = locals.get(oldName);
      if (l != null && (l.newName.equals(newName))) {
        l.type = type;
        l.newName = newName;
        return l;
      }

      LocalDef newLocal = new LocalDef(oldName, type, newName);
      locals.put(oldName, newLocal);
      return newLocal;
    }

    public String toString(String prefix, int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + prefix + "FUNC " + offset + " " + returnType + " " + name + "\n");
      for (var param : params) sb.append(" ".repeat(layer + 2) + param);
      for (var local : locals.values()) sb.append(" ".repeat(layer + 2) + local);

      return sb.toString();
    }

    @Override
    public String toString() {
      return toString("", 0);
    }
  }
  public static class VarDef {
    public String offset, type, name;

    public VarDef(String offset, String type, String name) {
      this.offset = offset;
      this.type = type;
      this.name = name;
    }

    public static VarDef getOrSet(List<VarDef> list, String offset, String type, String name) {
      for (VarDef v : list) {
        if (v.offset.equalsIgnoreCase(offset)) {
          v.type = type;
          v.name = name;
          return v;
        }
      }

      VarDef newVar = new VarDef(offset, type, name);
      list.add(newVar);
      return newVar;
    }

    public String toString(String prefix, int layer) {
      return " ".repeat(layer) + prefix + "VAR " + offset + " " + type + " " + name + "\n";
    }

    @Override
    public String toString() {
      return toString("", 0);
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
    public String offset, name;
    public Wildcardable superVTable, size;
    public List<VFuncDef> funcs;

    public VTableDef(String offset, String superVTable, String name, String size, List<VFuncDef> funcs) {
      this.offset = offset;
      this.superVTable = new Wildcardable(superVTable);
      this.name = name;
      this.size = new Wildcardable(size);
      this.funcs = funcs != null ? funcs : new ArrayList<>();
    }

    public VFuncDef getOrSetVFunc(int index, String offset, String returnType, String name, List<ParamDef> params, Map<String, LocalDef> locals) {
      for (VFuncDef vf : funcs) {
        if (vf.index == index) {
          vf.funcDef.offset = offset;
          vf.funcDef.returnType = returnType;
          vf.funcDef.name.update(name);
          if (params != null && !params.isEmpty()) vf.funcDef.params = params;
          if (locals != null && !locals.isEmpty()) vf.funcDef.locals = locals;
          return vf;
        }
      }

      FuncDef funcDef = new FuncDef(offset, returnType, name, params, locals);
      VFuncDef newVFunc = new VFuncDef(index, funcDef);
      funcs.add(newVFunc);
      return newVFunc;
    }

    public String toString(int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + "VTABLE " + offset + " " + superVTable + " " + name + " " + size + "\n");
      for (var vfunc : funcs) sb.append(vfunc.toString(layer + 2));

      return sb.toString();
    }
    
    @Override
    public String toString() {
      return toString(0);
    }
  }
  public static class VFuncDef {
    public int index;
    public FuncDef funcDef;

    public VFuncDef(int index, FuncDef funcDef) {
      this.index = index;
      this.funcDef = funcDef;
    }

    public ParamDef getOrSetParam(int index, String type, String name) {
      return funcDef.getOrSetParam(index, type, name);
    }

    public LocalDef getOrSetLocal(String oldName, String type, String newName) {
      return funcDef.getOrSetLocal(oldName, type, newName);
    }

    public String toString(int layer) {
      StringBuilder sb = new StringBuilder();

      sb.append(" ".repeat(layer) + "VFUNC " + index + " " + funcDef.offset + " " + funcDef.returnType + " " + funcDef.name + "\n");
      for (var param : funcDef.params) sb.append(" ".repeat(layer + 2) + param);
      for (var local : funcDef.locals.values()) sb.append(" ".repeat(layer + 2) + local);

      return sb.toString();
    }

    @Override
    public String toString() {
      return toString(0);
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

    @Override
    public String toString() {
      return toString(0);
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

  public static class Wildcardable {
    String value;

    public Wildcardable(String value) {
      this.value = (value != null) ? value : MappingUtil.WILDCARD;
    }

    public void update(String newVal) {
      update(newVal, false);
    }

    public void update(String newVal, boolean force) {
      boolean isOldWildcard = (value == null || value.equals(MappingUtil.WILDCARD));
      boolean isNewValid = (newVal != null && !newVal.equals(MappingUtil.WILDCARD));

      if (force || (isOldWildcard && isNewValid)) {
        this.value = (newVal != null) ? newVal : MappingUtil.WILDCARD;
      }
    }

    @Override
    public String toString() {
      return (value != null) ? value : MappingUtil.WILDCARD;
    }
  }
}