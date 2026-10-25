package com.sad.pvz2;

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.lang.Processor;

public class Mappings {
  private static final Map<String, String> classMappings = new HashMap<>();

  public static void loadMappings(File mappingDir, Processor proc, String gameVersion) {
    String arch = fromProcessor(proc);
    log(" > Mapping for Processor Arch: " + arch);
    loadMappings(new File(new File(mappingDir, arch), gameVersion + ".mapping"));
  }

  public static void loadMappings(File file) {
    try {
      List<String> lines = Files.readAllLines(file.toPath());
      for (String line : lines) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) continue;
      }
    }
    catch (IOException e) {
      error("Failed to read lines from mapping file", e);
    }
    log(classMappings.keySet().toString());
    log(classMappings.toString());
  }

  public static String fromProcessor(Processor proc) {
    return switch (proc.toString()) {
      case "AARCH64" -> "aarch64";
      default -> "";
    };
  }
}
