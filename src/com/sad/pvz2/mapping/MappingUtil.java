package com.sad.pvz2.mapping;

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.lang.Processor;

public class MappingUtil {
  public static String WILDCARD = "<>";

  public static MappingAST.MappingFile load(File mappingDir, Processor proc, String gameVersion) {
    String arch = fromProcessor(proc);
    MappingAST.MappingFile mappings = load(new File(new File(mappingDir, arch), gameVersion + ".mapping"));
    if (mappings != null) log(" > Loaded mappings for Processor Arch: " + arch);
    return mappings;
  }

  public static MappingAST.MappingFile load(File file) {
    try {
      List<String> lines = Files.readAllLines(file.toPath());
      return new Parser(lines).parse();
    }
    catch (IOException e) {
      error("Failed to read lines from mapping file", e);
    }
    return null;
  }

  public static boolean save(File mappingDir, Processor proc, String gameVersion, MappingAST.MappingFile mappings) {
    String arch = fromProcessor(proc);
    boolean saved = save(new File(new File(mappingDir, arch), gameVersion + ".mapping"), mappings);
    if (saved) log(" > Mapping saved for Processor Arch: " + arch);
    return saved;
  }

  public static boolean save(File file, MappingAST.MappingFile mappings) {
    try {
      Files.writeString(file.toPath(), mappings.serialize());
      return true;
    }
    catch (IOException e) {
      error("Failed to write mapping file", e);
    }
    return false;
  }

  public static String fromProcessor(Processor proc) {
    return switch (proc.toString()) {
      case "AARCH64" -> "aarch64";
      default -> "";
    };
  }

  private static class Parser {
    List<String> lines;
    int pos = 0;

    Parser(List<String> lines) {
      this.lines = lines;
    }

    MappingAST.MappingFile parse() {
      List<MappingAST.ClassDef> classes = new ArrayList<>();
      List<MappingAST.FuncDef> funcs = new ArrayList<>();
      List<MappingAST.VarDef> vars = new ArrayList<>();
      List<MappingAST.PtrDef> ptrs = new ArrayList<>();

      MappingAST.ClassDef currentClass = null;
      MappingAST.VTableDef currentVTable = null;
      MappingAST.FuncDef currentFunc = null;

      while (pos < lines.size()) {
        String rawLine = lines.get(pos++);
        String stripped = rawLine.strip();
        if (stripped.isEmpty() || stripped.startsWith("#")) continue;

        String[] tokens = stripped.split("\\s+");
        String keyword = tokens[0];

        switch (keyword) {
          // PTR <OFFSET> <TYPE>
          case "PTR" -> ptrs.add(new MappingAST.PtrDef(tokens[1], tokens[2]));
          // VAR <OFFSET> <TYPE> <IDENT>
          case "VAR" -> {
            var varDef = new MappingAST.VarDef(tokens[1], tokens[2], tokens[3]);
            if (currentClass != null) {
              currentClass.vars.add(varDef);
            }
            else {
              vars.add(varDef);
            }
          }
          // CLASS <IDENT> <SIZE>
          case "CLASS" -> {
            if (currentClass != null) classes.add(currentClass);
            currentClass = new MappingAST.ClassDef(
              tokens[1], tokens[2], null, new ArrayList<>(), new ArrayList<>(), new ArrayList<>()
            );
            currentVTable = null;
          }
          // VTABLE <OFFSET> <(parent vtable)IDENT> <IDENT> <SIZE>
          case "VTABLE" -> {
            currentVTable = new MappingAST.VTableDef(tokens[1], tokens[2], tokens[3], tokens[4], new ArrayList<>());
            if (currentClass != null) currentClass.vtable = currentVTable;
          }
          // FIELD <STARTING OFFSET> <TYPE> <IDENT>
          case "FIELD" -> {
            if (currentClass != null) currentClass.fields.add(new MappingAST.FieldDef(tokens[1], tokens[2], tokens[3]));
          }
          // S/FUNC <OFFSET> <TYPE> <IDENT>
          case "FUNC", "SFUNC" -> {
            currentFunc = new MappingAST.FuncDef(
              tokens[1], tokens[2], tokens[3], new ArrayList<>(), new ArrayList<>()
            );
            if (keyword.equals("SFUNC")) {
              funcs.add(currentFunc);
            }
            else if (currentClass != null) {
              currentClass.funcs.add(currentFunc);
            }
          }
          // VFUNC <INDEX> <OFFSET> <TYPE> <IDENT>
          case "VFUNC" -> {
            int index = Integer.parseInt(tokens[1]);
            var funcDef = new MappingAST.FuncDef(
              tokens[2], tokens[3], tokens[4], new ArrayList<>(), new ArrayList<>()
            );
            currentFunc = funcDef;
            if (currentVTable != null)
              currentVTable.funcs.add(new MappingAST.VFuncDef(index, funcDef));
          }
          // PARAM <INDEX> <TYPE> <IDENT>
          case "PARAM" -> {
            if (currentFunc != null)
              currentFunc.params.add(new MappingAST.ParamDef(Integer.parseInt(tokens[1]), tokens[2], tokens[3]));
          }
          // LOCAL <(old)IDENT> <TYPE> <IDENT>
          case "LOCAL" -> {
            if (currentFunc != null)
              currentFunc.locals.add(new MappingAST.LocalDef(tokens[1], tokens[2], tokens[3]));
          }
        }
      }

      if (currentClass != null) classes.add(currentClass);

      return new MappingAST.MappingFile(classes, funcs, vars, ptrs);
    }
  }
}
