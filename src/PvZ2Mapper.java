//Ghidra script for mapping the 64 bit libPvZ2.so
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
import com.sad.pvz2.util.StructUtil;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.PointerTypedef;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;

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

    for (MappingAST.ClassDef classDef : MAPPINGS.classes())
      if (classDef != null) mapClass(classDef);

    // TODO: Add sfunc/svar/ptr maps
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
        String shortName = getShortName(fullName);

        StructureDataType struct = StructUtil.getOrCreateStructure(dtm, catPath, shortName, b -> {
          // TODO: add the fields from def
        });

        log("Created Structure Class: " + fullName + " [Size: " + def.size + "]");
      }
      catch (Exception e) {
        error("Failed to create structure for " + fullName + ": ", e);
      }
    }
  }

  public static CategoryPath getCategoryPath(String fullName) {
    int lastIdx = fullName.lastIndexOf("::");
    if (lastIdx == -1) return new CategoryPath(PVZ2_CATEGORY_PATH);

    String subPath = fullName.substring(0, lastIdx).replace("::", "/");
    return new CategoryPath(PVZ2_CATEGORY_PATH + "/" + subPath);
  }

  public static String getShortName(String fullName) {
    int lastIdx = fullName.lastIndexOf("::");
    return (lastIdx == -1) ? fullName : fullName.substring(lastIdx + 2);
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