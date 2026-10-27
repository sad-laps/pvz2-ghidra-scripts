//Ghidra script for writing mapped information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.mapping.MappingAST;
import com.sad.pvz2.mapping.MappingUtil;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
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
    map();
    MappingUtil.save(MAPPING_DIR, currentProgram.getLanguage().getProcessor(), GAME_VERSION, MAPPINGS);
  }

  public static void map() {
    // Search defined symbols in symbol tree first
    SymbolIterator symbols = symTab.getDefinedSymbols();

    for (Symbol sym : symbols) {
      if (!sym.getParentNamespace().isGlobal()) continue;
      if (sym.getSource() != SourceType.USER_DEFINED) continue;
      if (sym.getSymbolType() != SymbolType.NAMESPACE && sym.getSymbolType() != SymbolType.FUNCTION) continue;

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

    SymbolType type = sym.getSymbolType();
    String name = sym.getName();

    switch (type.toString()) {
      case "Label" -> log("Found Label: " + name);
      case "Function" -> log("Found Function: " + name + " at " + (addr != null ? addr : "N/A"));
      default -> log("Unhandled symbol type: " + type + " for " + name);
    }
  }

  public static MappingAST.ClassDef mapClass(String fullName, String name) {
    String size = MappingUtil.WILDCARD;
    String dtPath = "/" + fullName.replace("::", "/") + "/" + name;
    try {
      DataType dt = dtm.getDataType(PVZ2_CATEGORY_PATH + dtPath);
      size = "0x" + Integer.toHexString(dt.getLength());
    }
    catch (Exception e) {
    }

    return MAPPINGS.getOrAddClass(fullName, size);
  }
}