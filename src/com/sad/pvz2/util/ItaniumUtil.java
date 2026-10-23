package com.sad.pvz2.util;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.CategoryPath;

/**
 * Helper method to demangle Itanium type names.
 * Written with AI Assistance (Gemini)
 */
public class ItaniumUtil {
  public static ClassNameInfo demangleItaniumString(String raw) {
    if (raw == null || raw.isEmpty()) return new ClassNameInfo("", "");

    List<String> parts = new ArrayList<>();
    if (raw.startsWith("N") && raw.endsWith("E")) {
      int i = 1; // Skip 'N'

      while (i < raw.length() - 1) {
        int len = 0;
        // Parse the length digits
        while (i < raw.length() - 1 && Character.isDigit(raw.charAt(i))) {
          len = len * 10 + (raw.charAt(i) - '0');
          i++;
        }
        if (len == 0) break;

        // Extract the identifier string segment
        if (i + len <= raw.length() - 1) {
          String identifier = raw.substring(i, i + len);
          parts.add(identifier);
          i += len;
        }
        else {
          break;
        }
      }
    }
    else if (Character.isDigit(raw.charAt(0))) {
      int len = 0;
      int i = 0;
      while (i < raw.length() && Character.isDigit(raw.charAt(i))) {
        len = len * 10 + (raw.charAt(i) - '0');
        i++;
      }
      if (i + len <= raw.length()) {
        parts.add(raw.substring(i, i + len));
      }
    }
    else {
      parts.add(raw);
    }

    if (parts.isEmpty())
      return new ClassNameInfo("", raw);

    String className = parts.get(parts.size() - 1);
    List<String> nsParts = parts.subList(0, parts.size() - 1);
    String namespace = String.join("::", nsParts);

    return new ClassNameInfo(namespace, className);
  }
  
  public record ClassNameInfo(String namespace, String name) {
    public String getFullName() {
      return (namespace != null && !namespace.isEmpty()) ? namespace + "::" + name : name;
    }

    public CategoryPath toCategoryPath(CategoryPath rootCategory) {
      if (namespace == null || namespace.isEmpty()) return new CategoryPath(rootCategory.getPath() + "/" + name);

      String subPath = namespace.replace("::", "/");
      return new CategoryPath(rootCategory.getPath() + "/" + subPath);
    }
  }
}
