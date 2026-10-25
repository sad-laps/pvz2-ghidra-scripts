//Ghidra script for writing mapped information from the 64 bit libPvZ2.so
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import com.sad.pvz2.Mappings;
import com.sad.pvz2.PvZ2BaseScript;

public class PvZ2MapWriter extends PvZ2BaseScript {
  @Override
  protected void run() {
    init("26.0.0", "13.5.1", "pvz2mapwriter_output.log");
    logHeader("PvZ2 Map-Writer", SCRIPT_VERSION, GAME_VERSION);

    Mappings.loadMappings("/mnt/data/Projects/Ghidra/GhidraScripts/mappings/" + GAME_VERSION + ".mapping");
  }
}