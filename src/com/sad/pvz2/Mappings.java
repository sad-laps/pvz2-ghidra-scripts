package com.sad.pvz2;

import static com.sad.pvz2.ScriptLogger.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Mappings {
  private static final Map<String, String> classMappings = new HashMap<>();

  public static void loadMappings(String filePath) {
    loadMappings(new File(filePath));
  }

  public static void loadMappings(File file) {
    try {
      List<String> lines = Files.readAllLines(file.toPath());
      for (String line : lines) {
        line = line.trim();
        if (line.isEmpty() || line.startsWith("#")) continue;

        String[] parts = line.split(" ", 3);
        classMappings.put(parts[1], parts[2]);
      }
    }
    catch (IOException e) {
      error("Failed to read lines from mapping file", e);
    }
    log(classMappings.keySet().toString());
    log(classMappings.toString());
  }
}
