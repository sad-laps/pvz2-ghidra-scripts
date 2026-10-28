//Ghidra script for mapping the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.mapping.MappingAST;
import com.sad.pvz2.mapping.MappingUtil;
import com.sad.pvz2.util.StructUtil;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;

public class PvZ2Mapper extends PvZ2BaseScript {
  // Itanium C++ ABI Data Types
  public static StructureDataType typeInfo;
  public static StructureDataType classTypeInfo;
  public static StructureDataType siClassTypeInfo;
  public static StructureDataType baseClassTypeInfo;
  public static StructureDataType vmiClassTypeInfo;

  public static File MAPPING_DIR;
  public static MappingAST.MappingFile MAPPINGS;

  @Override
  protected void run() {
    init("26.0.0", "13.5.2", "pvz2mapper_output.log");
    logHeader("PvZ2 Map-Writer", SCRIPT_VERSION, GAME_VERSION);

    // Create the Itanium C++ ABI structures beforehand
    initItaniumABIStructures();

    MAPPING_DIR = new File(scriptDir.getParentFile(), "mappings");
    MAPPINGS = MappingUtil.load(MAPPING_DIR, currentProgram.getLanguage().getProcessor(), GAME_VERSION);
    divider();
    log(MAPPINGS.serialize());
    divider();
    map();
  }

  /**
   * Creates the Itanium C++ ABI structures.
   */
  public static Boolean initializedItanium = false;
  public static void initItaniumABIStructures() {
    CategoryPath rttiPath = new CategoryPath("/_ItaniumABI");

    if (dtm.getDataType(rttiPath, "type_info") == null) initializedItanium = false;

    PointerTypedef offsetRttiPtr = new PointerTypedef("pointer_offset+0x10", UNDEFINED_POINTER_TYPE, 8, dtm, 16);
    // std::type_info (Type Info)
    typeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "type_info", b -> {
      b.add(offsetRttiPtr, 8, "__vptr_type_info", "");
      b.add(new PointerDataType(CharDataType.dataType), 8, "__type_name", "");
    });

    // __class_type_info (Class Type Info)
    classTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__class_type_info", b -> b.add(typeInfo, typeInfo.getLength(), "type_info", ""));

    // __si_class_type_info (Single Inheritance Class Type Info)
    siClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__si_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
    });

    // __base_class_type_info (Base Class Type Info (for vmi))
    baseClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__base_class_type_info", b -> {
      b.add(new PointerDataType(classTypeInfo), 8, "__base_type", "");
      // baseClassTypeInfo.add(LongDataType.dataType, 8, "__offset_flags", "");
      // Use `longlong` because Ghidra forces the `long` bitfields to 0x4 size in scripts bruh
      b.addBitField(LongLongDataType.dataType, 4, "__virtual", "");
      b.addBitField(LongLongDataType.dataType, 4, "__public", "");
      b.addBitField(LongLongDataType.dataType, 48, "__offset", "");
    });

    // TODO: Will have to create for each base dynamically  when needed later on!!
    // __vmi_class_type_info (Virtual and Multiple Inheritance Class Type Info)
    vmiClassTypeInfo = StructUtil.getOrCreateStructure(dtm, rttiPath, "__vmi_class_type_info", b -> {
      b.add(typeInfo, typeInfo.getLength(), "type_info", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__flags", "");
      b.add(UnsignedIntegerDataType.dataType, 4, "__base_count", "");
      b.add(new ArrayDataType(baseClassTypeInfo, 1, baseClassTypeInfo.getLength()), "__base_info", "");
    });

    if (!initializedItanium) log(" * Initialized Itanium C++ ABI structures.");
    initializedItanium = true;
  }

  public static void map() {
    if (MAPPINGS == null) return;

    for (MappingAST.PtrDef ptr : MAPPINGS.ptrs())
      if (ptr != null) mapPointer(ptr);

    for (MappingAST.FuncDef sfunc : MAPPINGS.sfuncs()) 
      if (sfunc != null) mapFunction(null, sfunc);

    for (MappingAST.VarDef svar : MAPPINGS.svars()) 
      if (svar != null) mapVariable(null, svar);

    for (MappingAST.ClassDef classDef : MAPPINGS.classes())
      if (classDef != null) mapClass(classDef);
  }

  public static void mapClass(MappingAST.ClassDef def) {
    String fullName = def.name;

    boolean isNamespaceOnly = def.size.toString().equals(MappingUtil.WILDCARD);

    String pathStr = PVZ2_CATEGORY_PATH + "/" + fullName.replace("::", "/");
    CategoryPath catPath = new CategoryPath(pathStr);

    if (isNamespaceOnly) {
      // If size is <> treat it as a namespace / empty category container
      dtm.createCategory(catPath);
      log("Created Namespace Category: " + catPath);
    }
    else {
      try {
        dtm.createCategory(catPath);
        log("Created Namespace Category: " + catPath);
        String shortName = getShortName(fullName);

        // Map the VTable first as it could be used by the fields
        if (def.vtable != null) mapVTable(fullName, catPath, def.vtable);

        // Map the class related functions
        if (def.funcs != null) {
          for (MappingAST.FuncDef funcDef : def.funcs) mapFunction(fullName, funcDef);
        }

        if (def.vars != null)
          for (MappingAST.VarDef varDef : def.vars) mapVariable(fullName, varDef);

        // Map the Class fields
        StructUtil.getOrCreateStructure(dtm, catPath, shortName, b -> {
          for (MappingAST.FieldDef field : def.fields) {
            int offset = Integer.decode(field.startOffset);
            DataType dataType = resolveDataType(field.type);
            b.insertAtOffset(offset, dataType, dataType.getLength(), field.name, "");
          }
        });

        log("Created Structure Class: " + fullName + " [Size: " + def.size + "]");
      }
      catch (Exception e) {
        error("Failed to create structure for " + fullName + ": ", e);
      }
    }
  }

  public static void mapVTable(String className, CategoryPath catPath, MappingAST.VTableDef vtableDef) {
    String vtName = vtableDef.name;

    try {
      StructureDataType vtStruct = StructUtil.getOrCreateStructure(dtm, catPath, vtName, b -> {
        for (MappingAST.VFuncDef vfunc : vtableDef.funcs) {
          int offset = vfunc.index * PTR_SIZE;
          String fnName = vfunc.funcDef.name.toString();

          FunctionDefinitionDataType fnDef = mapFunction(className, vfunc.funcDef, catPath);
          DataType slotType = (fnDef != null) ? new PointerDataType(fnDef, PTR_SIZE) : UNDEFINED_POINTER_TYPE;
          b.insertAtOffset(offset, slotType, PTR_SIZE, fnName, "");
        }
      });

      Address vtAddr = getAddrFromRva(vtableDef.offset);
      changeDataType(vtAddr, vtStruct);
      setLabel(vtAddr, className, vtName);

      log("Created VTable Structure: " + vtName + " [Size: " + vtableDef.size.toString() + ", Slots: " + vtableDef.funcs.size() + "]");
    }
    catch (Exception e) {
      error("Failed to create VTable structure " + vtName + ": ", e);
    }
  }
  
  // TODO: Fix thunks not using namespace and t_FunctionName (might actually not even map them lol)
  // TODO: check for `this` parameter and make the function best a __thiscall function!
  public static FunctionDefinitionDataType mapFunction(String className, MappingAST.FuncDef def, CategoryPath catPath) {
    if (def == null || def.offset == null || def.offset.equals(MappingUtil.WILDCARD)) return null;

    Address addr = getAddrFromRva(def.offset);
    if (addr == null) return null;

    try {
      Function func = program.getFunctionManager().getFunctionAt(addr);

      if (func == null) return null;
      DataType returnType = resolveDataType(def.returnType);
      if (returnType == UNDEFINED_POINTER_TYPE) returnType = func.getReturnType();

      String fnName = def.name.toString();
      if (!fnName.equals(MappingUtil.WILDCARD))
        setLabel(addr, (className != null) ? className : "", fnName);

      FunctionDefinitionDataType fnDef = new FunctionDefinitionDataType(fnName);
      fnDef.setReturnType(returnType);

      // TODO: Map Locals

      // Commit parameters from decomp as the assembly doesn't have it for some reason
      DecompileResults res = decomp.decompileFunction(func, 30, null);
      if (res != null && res.decompileCompleted()) {
        HighFunction highFunc = res.getHighFunction();
        if (highFunc != null) {
          HighFunctionDBUtil.commitParamsToDatabase(highFunc, true, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED);
        }

        Iterator<HighSymbol> symbols = highFunc.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
          HighSymbol symbol = symbols.next();
          if (symbol == null || symbol.isParameter()) continue;

          String currentName = symbol.getName();
          log(" Mapped Parameter: " );

          MappingAST.LocalDef localDef = def.locals.get(currentName);
          if (localDef == null) continue;

          DataType lType = resolveDataType(localDef.type);
          if (lType == null) lType = symbol.getDataType();

          String newName = (localDef.newName != null && !localDef.newName.equals(MappingUtil.WILDCARD)) 
              ? localDef.newName 
              : currentName;

          try {
            HighFunctionDBUtil.updateDBVariable(symbol, newName, lType, SourceType.USER_DEFINED);
            log(" Mapped Local Variable: " + currentName + " -> " + newName);
          }
          catch (Exception e) {
            error("Failed to update local variable " + currentName, e);
          }
        }
      }

      Parameter[] existingParams = func.getParameters();
      List<ParameterDefinition> paramDefList = new ArrayList<>();
      for (Parameter ep : existingParams) {
        paramDefList.add(new ParameterDefinitionImpl(ep.getName(), ep.getDataType(), null));
      }

      if (def.params != null) {
        for (MappingAST.ParamDef paramDef : def.params) {
          DataType pType = resolveDataType(paramDef.type);

          String pName = (paramDef.name != null && !paramDef.name.equals(MappingUtil.WILDCARD)) 
            ? paramDef.name : "param_" + paramDef.index;

          // Set __thiscall as calling convention to automatically apply `this` as first param
          // if (paramDef.index == 0 && (pName.equals("self") || pName.equals("this"))) {
          //   paramDefList.remove(0);
          //   fnDef.setCallingConvention("__thiscall");
          //   log(" * Changed calling convention -> __thiscall");
          //   continue;
          // }

          ParameterDefinition newParamDef = new ParameterDefinitionImpl(pName, pType, null);

          paramDefList.set(paramDef.index, newParamDef);
          log(" Mapped Parameter: " + pName);
        }
      }
      ParameterDefinition[] paramDefs = paramDefList.toArray(new ParameterDefinition[0]);
      fnDef.setArguments(paramDefs);

      // Save Function Description in Category
      if (catPath != null) 
        fnDef.setCategoryPath(catPath);
      else if (className != null)
        fnDef.setCategoryPath(getCategoryPath(className));
      else
        fnDef.setCategoryPath(new CategoryPath("/_PvZ2Functions"));

      ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(addr, fnDef, SourceType.USER_DEFINED);

      boolean success = cmd.applyTo(program);
      if (!success) {
        error("Failed to apply function definition for " + fnName + ": " + cmd.getStatusMsg(), null);
      }
      else {
        log("Mapped Function: " + (className != null ? className + "::" : "") + fnName + " at " + addr);
      }

      return fnDef;
    }
    catch (Exception e) {
      error("Failed to map function " + def.name + " at 0x" + addr + ": ", e);
    }
    return null;
  }

  public static FunctionDefinitionDataType mapFunction(String className, MappingAST.FuncDef def) {
    return mapFunction(className, def, null);
  }
  
  public static void mapVariable(String className, MappingAST.VarDef def) {
    if (def == null || def.offset == null || def.offset.equals(MappingUtil.WILDCARD)) return;

    Address addr = getAddrFromRva(def.offset);
    if (addr == null) return;

    try {
      DataType dataType = resolveDataType(def.type);
      if (dataType != null) changeDataType(addr, dataType);
      if (def.name != null && !def.name.isEmpty()) setLabel(addr, className, def.name);

      log("Mapped Variable: " + className + "::" + def.name + " at " + addr);
    }
    catch (Exception e) {
      error("Failed to map variable " + def.name + " at 0x" + addr + ": ", e);
    }
  }
  
  public static void mapPointer(MappingAST.PtrDef def) {
    if (def == null || def.offset == null || def.offset.equals(MappingUtil.WILDCARD)) return;

    Address addr = getAddrFromRva(def.offset);
    if (addr == null) return;

    try {
      DataType dataType = resolveDataType(def.type);
      if (dataType != null) changeDataType(addr, dataType);

      log("Mapped Pointer: " + " at " + def.offset);
    }
    catch (Exception e) {
      error("Failed to map pointer at 0x" + addr + ": ", e);
    }
  }

  public static DataType resolveDataType(String typeName) {
    if (typeName == null || typeName.isEmpty()) return null;

    if (typeName.endsWith("*")) {
      String baseTypeName = typeName.substring(0, typeName.length() - 1).strip();
      DataType baseDt = resolveDataType(baseTypeName);
      return new PointerDataType(baseDt != null ? baseDt : null, PTR_SIZE);
    }

    DataType dt = dtm.getDataType(typeName);
    if (dt != null) return dt;

    List<DataType> matches = new ArrayList<>();
    dtm.findDataTypes(typeName, matches);
    if (!matches.isEmpty()) return matches.get(0);

    return UNDEFINED_POINTER_TYPE;
  }

  public static String getShortName(String fullName) {
    int lastIdx = fullName.lastIndexOf("::");
    return (lastIdx == -1) ? fullName : fullName.substring(lastIdx + 2);
  }

  public static CategoryPath getCategoryPath(String fullName) {
    if (fullName == null || fullName.isEmpty()) return new CategoryPath(PVZ2_CATEGORY_PATH);

    String pathStr = PVZ2_CATEGORY_PATH + "/" + fullName.replace("::", "/");
    return new CategoryPath(pathStr);
  }

  public static Address getAddrFromRva(String rvaOffset) {
    if (rvaOffset == null || rvaOffset.equals(MappingUtil.WILDCARD)) return null;
    try {
      long rva = Long.decode(rvaOffset);
      long imageBase = program.getImageBase().getOffset();
      long absAddrVal = imageBase + rva;

      return addr.getDefaultAddressSpace().getAddress(absAddrVal);
    }
    catch (Exception e) {
      error("Failed to parse RVA offset: " + rvaOffset, e);
      return null;
    }
  }
}