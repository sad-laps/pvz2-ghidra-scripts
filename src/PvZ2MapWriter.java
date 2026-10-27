//Ghidra script for mapping information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.mapping.MappingAST;
import com.sad.pvz2.mapping.MappingUtil;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

public class PvZ2MapWriter extends PvZ2BaseScript {
  public static File MAPPING_DIR;
  public static MappingAST.MappingFile MAPPINGS;

  @Override
  protected void run() {
    init("26.0.0", "13.5.2", "pvz2mapwriter_output.log");
    logHeader("PvZ2 Map-Writer", SCRIPT_VERSION, GAME_VERSION);
    MAPPING_DIR = new File(scriptDir.getParentFile(), "mappings");
    MAPPINGS = MappingUtil.load(MAPPING_DIR, currentProgram.getLanguage().getProcessor(), GAME_VERSION);
    // divider();
    // log(MAPPINGS.serialize());
    // divider();
    map();
    // divider();
    // log(MAPPINGS.serialize());
    // divider();
    MappingUtil.save(MAPPING_DIR, currentProgram.getLanguage().getProcessor(), GAME_VERSION, MAPPINGS);
  }

  public static void map() {
    // Search defined symbols in symbol tree first
    SymbolIterator symbols = symTab.getDefinedSymbols();

    for (Symbol sym : symbols) {
      if (!sym.getParentNamespace().isGlobal()) continue;
      if (sym.getSource() != SourceType.USER_DEFINED) continue;
      if (sym.getSymbolType() != SymbolType.NAMESPACE 
        && sym.getSymbolType() != SymbolType.FUNCTION 
        && sym.getSymbolType() != SymbolType.LABEL) continue;

      mapSymbolsRecursively(sym, "", null);
    }
  }

  public static void mapSymbolsRecursively(Symbol sym, String superName, MappingAST.ClassDef currentClass) {
    SymbolType type = sym.getSymbolType();

    if (type == SymbolType.LOCAL_VAR || type == SymbolType.PARAMETER) return;

    String name = sym.getName();
    String fullName = superName.isEmpty() ? name : superName + "::" + name;

    if (type == SymbolType.NAMESPACE) {
      currentClass = mapClass(fullName, name);
    }
    else {
      mapSymbol(sym, currentClass);
    }

    SymbolIterator subSymbols = symTab.getChildren(sym);
    while (subSymbols.hasNext()) {
      Symbol subSym = subSymbols.next();
      mapSymbolsRecursively(subSym, fullName, currentClass);
    }
  }

  public static void mapSymbol(Symbol sym, MappingAST.ClassDef currentClass) {
    Address addr = sym.getAddress();
    String offset = getRvaOffset(addr);
    SymbolType type = sym.getSymbolType();
    String name = sym.getName();

    switch (type.toString()) {
      case "Label" -> {
        DataType dataType = listing.getDataAt(addr).getDataType();
        String typeName = (dataType != null) ? dataType.getDisplayName() : "undefined8";

        // Add Variables / Global Variables
        if (currentClass == null) {
          MAPPINGS.getOrSetSVar(offset, typeName, name);
        }
        else {
          // Handle VTables
          if ((name.endsWith("VTable") || typeName.endsWith("VTable"))) {
            String vtSize = (dataType != null) ? "0x" + Integer.toHexString(dataType.getLength()) : MappingUtil.WILDCARD;
            MappingAST.VTableDef vtableDef = currentClass.getOrSetVTable(offset, MappingUtil.WILDCARD, name, vtSize);
            if (dataType instanceof Structure vtableStruct) mapVTable(addr, vtableDef, vtableStruct);
          }
          else currentClass.getOrSetVar(offset, typeName, name);
        }
      }
      case "Function" -> {
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null) {
          String returnType = func.getReturnType().getDisplayName();
          MappingAST.FuncDef targetFuncDef;

          if (currentClass == null) {
            targetFuncDef = MAPPINGS.getOrSetSFunc(offset, returnType, name);
          }
          else {
            if (currentClass.hasVFuncAtOffset(offset)) return;
            targetFuncDef = currentClass.getOrSetFunc(offset, returnType, name);
          }
          populateFuncDef(func, targetFuncDef);
        }
      }
      default -> log("Unhandled symbol type: " + type + " for " + name);
    }
  }
  
  public static void mapVTable(Address addr, MappingAST.VTableDef def, Structure struct) {
    int index = 0;

    for (DataTypeComponent comp : struct.getComponents()) {
      long compOffset = comp.getOffset();
      String vfuncName = comp.getFieldName();
      if (vfuncName == null || vfuncName.isEmpty()) vfuncName = "vfunc_" + index;

      try {
        Address vfuncAddr = addr.add(compOffset);
        long targetFnAddrVal = mem.getLong(vfuncAddr);
        Address targetFnAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(targetFnAddrVal);
        if (targetFnAddr != null) {
          Function func = program.getFunctionManager().getFunctionAt(targetFnAddr);

          MappingAST.VFuncDef prevFn = def.getOrSetVFunc(index, getRvaOffset(targetFnAddr), func.getReturnType().getDisplayName(), func.getName(), null, null);
          if (func != null) populateFuncDef(func, prevFn.funcDef);
        }
      }
      catch (Exception e) {
        error("Faile to map VTable: ", e);
      }

      index++;
    }
  }

  public static void populateFuncDef(Function func, MappingAST.FuncDef funcDef) {
    int pidx = 0;
    for (Parameter param : func.getParameters()) {
      if (param == null) continue;
      funcDef.getOrSetParam(pidx, param.getDataType().getDisplayName(), param.getName());
      pidx++;
    }

    for (Variable local : func.getLocalVariables()) {
      if (local == null) continue;
      funcDef.getOrSetLocal(MappingUtil.WILDCARD, local.getDataType().getDisplayName(), local.getName());
    }
  }

  public static MappingAST.ClassDef mapClass(String fullName, String name) {
    String size = MappingUtil.WILDCARD;
    String dtPath = "/" + fullName.replace("::", "/") + "/" + name;
    List<MappingAST.FieldDef> fields = new ArrayList<>();
    try {
      DataType dt = dtm.getDataType(PVZ2_CATEGORY_PATH + dtPath);
      size = "0x" + Integer.toHexString(dt.getLength());

      if (dt instanceof Structure struct) {
        for (DataTypeComponent comp : struct.getComponents()) {
          String offset = "0x" + Long.toHexString(comp.getOffset());
          String type = comp.getDataType().getDisplayName();
          String fieldName = comp.getFieldName();

          if (fieldName == null || fieldName.isEmpty()) fieldName = "field_" + offset;

          fields.add(new MappingAST.FieldDef(offset, type, fieldName));
        }
      }
    }
    catch (Exception e) {
    }

    return MAPPINGS.getOrAddClass(fullName, size, fields);
  }

  public static String getRvaOffset(Address addr) {
    if (addr == null) return MappingUtil.WILDCARD;
    long imageBase = program.getImageBase().getOffset();
    long rva = addr.getOffset() - imageBase;
    return String.format("0x%08x", rva);
  }
}