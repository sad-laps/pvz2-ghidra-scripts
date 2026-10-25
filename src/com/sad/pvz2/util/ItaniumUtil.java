package com.sad.pvz2.util;

// import static com.sad.pvz2.ScriptLogger.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for helping with the Itanium C++ ABI.
 */
public class ItaniumUtil {
  public static String[] ITANIUM_SYMBOLS = {
    "_ZTVN10__cxxabiv117__class_type_infoE",
    "_ZTVN10__cxxabiv120__si_class_type_infoE",
    "_ZTVN10__cxxabiv121__vmi_class_type_infoE"
  };

  public static SymbolInfo demangle(String raw) {
    if (raw == null || raw.isEmpty()) return SymbolInfo.EMPTY;
    // if (raw.startsWith("NSt")) return SymbolInfo.EMPTY;
    
    SymbolInfo demangled = new Demangler(raw).demangleSymbol();
    return demangled;
  }

  public record SymbolInfo(String namespace, String name) {
    public static SymbolInfo EMPTY = new SymbolInfo("", "");

    public String getFullName() {
      return (namespace != null && !namespace.isEmpty()) ? namespace + "::" + name : name;
    }
  }

  private static class Demangler {
    String data;
    int pos = 0;
    char currentChar;

    Demangler(String data) {
      this.data = data;
      updateCurrentChar();
    }

    void updateCurrentChar() {
      currentChar = pos < data.length() ? data.charAt(pos) : '\0';
    }

    void advance() { pos++; updateCurrentChar(); }
    boolean match(char c) { return currentChar == c; }

    boolean matchAndConsume(char c) {
      if (match(c)) {
        advance();
        return true;
      }
      return false;
    }

    SymbolInfo demangleSymbol() {
      if (data.length() == 0) return SymbolInfo.EMPTY;

      String fullName = parseName();
      // log("Parsed Result from: " + data);
      // log("-> " + fullName);
      // for (int i = 0; i < substitutions.size(); i++) {
      //   String code = (i == 0) ? "S_" : "S" + (i - 1) + "_";
      //   log("  [" + i + "] " + code + " = " + substitutions.get(i));
      // }
      // log("---------------------------------------------");

      if (fullName == null || fullName.isEmpty()) return SymbolInfo.EMPTY;

      int lastIdx = fullName.lastIndexOf("::");
      if (lastIdx != -1)
        return new SymbolInfo(fullName.substring(0, lastIdx), fullName.substring(lastIdx + 2));

      return new SymbolInfo("", fullName);
    }

    List<String> substitutions = new ArrayList<>();
    void addSubstitution(String s) {
      if (s != null && !s.isEmpty()) {
        substitutions.add(s);
      }
    }
    String getSubstitution(int index) {
      if (index >= 0 && index < substitutions.size()) return substitutions.get(index);
      return "S" + index + "_"; // Fallback if out of bounds
    }

    // Parses the <name>
    private String parseName() {
      if (Character.isDigit(currentChar)) // <source-name> = <positive length number> <identifier>
        return parseSourceName();

      char c = currentChar;
      advance();

      String result = switch (c) {
        case 'N' -> parseNestedName();  // <nested-name> = N ... E
        case 'S' -> parseSubstitution(); 
        case 'U' -> parseClosureTypeName();      // <closure-type-name> = Ul <lambda-sig> E [ <nonnegative number> ] _ 
        case 'F' -> parseFunctionType();         // <function-type> = F ... [Y] <bare-function-type> [<ref-qualifier>] E
        case 'Z' -> parseLocalName();            // <local-name> = Z ... E <entity name>/s [<discriminator>]
        case 'K' -> parseType(" const"); // <CV-qualifiers> = [K]  #  const
        case 'R' -> parseType("&");      // <type> = R <type>      # l-value reference
        case 'P' -> parseType("*");      // <type> = P <type>      # pointer
        case 'v' -> "void";                     // <builtin-type> = v     # void
        case 'b' -> "bool";                     // <builtin-type> = b     # bool
        case 'i' -> "int";                      // <builtin-type> = i	    # int
        case 'f' -> "float";                    // <builtin-type> = f     # float
        case 'l' -> "long";                     // <builtin-type> = l	    # long
        case 'c' -> {
          if (matchAndConsume('l')) {
            yield "operator()";
          }
          yield "char";                         // <builtin-type> = c     # char
        }
        default -> {
          // log("Couldn't interpret " + c);
          yield String.valueOf(c);
        }
      };

      return result;
    }
    
    private String parseSubstitution() {
      String res;
      if (matchAndConsume('t')) { // <unscoped-name> = St <unqualified-name>   # ::std::
        String subName = parseName();
        res = "std::" + subName;
      }
      else {  // <substitution> = S<seq-id>_ or S_
        int seqId = 0;
        if (currentChar != '_') {
          int base36Val = 0;
          while (currentChar != '\0' && currentChar != '_') {
            char sc = currentChar;
            int digitVal = (sc >= '0' && sc <= '9') ? sc - '0' : 
              (sc >= 'A' && sc <= 'Z') ? sc - 'A' + 10 : 
              (sc >= 'a' && sc <= 'z') ? sc - 'a' + 10 : 0;
            base36Val = base36Val * 36 + digitVal;
            advance();
          }
          seqId = base36Val + 1;
        }
        matchAndConsume('_');
        res = getSubstitution(seqId);
      }

      if (matchAndConsume('I')) {
        List<String> templateArgs = new ArrayList<>();
        while (currentChar != '\0' && !match('E')) {
          templateArgs.add(parseName());
        }
        matchAndConsume('E');
        res += "<" + String.join(", ", templateArgs) + ">";
      }

      return res;
    }

    private String parseClosureTypeName() {
      if (matchAndConsume('l')) {
        List<String> lambdaSig = new ArrayList<>();
        while (currentChar != '\0' && !match('E')) {
          lambdaSig.add(parseName());
        }
        matchAndConsume('E');
        matchAndConsume('_');
        return "{lambda()#1}";
      }
      else {
        String subName = parseName();
        return subName;
      }
    }

    private String parseFunctionType() {
      List<String> funcTypes = new ArrayList<>();
      while (currentChar != '\0' && !match('E')) {
        funcTypes.add(parseName());
      }
      matchAndConsume('E');

      String returnType = funcTypes.isEmpty() ? "void" : funcTypes.get(0);

      List<String> params = funcTypes.size() > 1 ? funcTypes.subList(1, funcTypes.size()) : List.of();

      if (params.size() == 1 && params.get(0).equals("void")) {
        params = List.of();
      }

      String sig = returnType + "(" + String.join(", ", params) + ")";
      addSubstitution(sig);

      return sig;
    }

    private String parseType(String suffix) {
      String typeName = parseName() + suffix;
      addSubstitution(typeName);
      return typeName;
    }

    private String parseNestedName() {
      List<String> idents = new ArrayList<>();

      while (currentChar != '\0' && !match('E')) {
        String id = parseName();
        idents.add(id);

        String partialNested = String.join("::", idents);
        addSubstitution(partialNested);
      }
      matchAndConsume('E');

      return String.join("::", idents);
    }

    private String parseLocalName() {
      // Parse the function or operator name part of the encoding
      String enclosing = parseName();

      List<String> paramTypes = new ArrayList<>();
      while (currentChar != '\0' && !match('E')) {
        paramTypes.add(parseName());
      }
      matchAndConsume('E');

      String entityName = parseName();

      if (!paramTypes.isEmpty()) {
        String paramsStr = String.join(", ", paramTypes);
        if (enclosing.contains("operator()")) {
          enclosing = enclosing.replace("operator()", "operator(" + paramsStr + ")");
        }
        else if (!enclosing.endsWith(")")) {
          enclosing = enclosing + "(" + paramsStr + ")";
        }
      }

      String separator = (enclosing.endsWith(")") || enclosing.contains("operator")) ? "::" : "()::";
      String result = enclosing + separator + entityName;
      
      addSubstitution(result);
      return result;
    }

    private String parseSourceName() {
      int length = 0;

      while (Character.isDigit(currentChar)) {
        length = length * 10 + (currentChar - '0');
        advance();
      }

      int startIndex = pos;
      for (int i = 0; i < length; i++) advance(); 
      if (length <= 0 || startIndex + length > data.length()) return "";

      String id = data.substring(startIndex, startIndex + length);

      if (matchAndConsume('I')) { // <template-args>
        List<String> templateArgs = new ArrayList<>();
        while (currentChar != '\0' && !match('E')) {
          templateArgs.add(parseName());
        }
        matchAndConsume('E');
        id += "<" + String.join(", ", templateArgs) + ">";
      }

      addSubstitution(id);
      return id;
    }
  }
}