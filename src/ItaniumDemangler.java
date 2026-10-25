//Desc
//@author sad
//@category PvZ2 Tools
//@keybinding
//@menupath
//@toolbar
//@runtime Java

import static com.sad.pvz2.ScriptLogger.*;

import java.util.Optional;

import com.sad.pvz2.PvZ2BaseScript;
import com.sad.pvz2.util.ItaniumUtil;

import ghidra.program.model.address.Address;

public class ItaniumDemangler extends PvZ2BaseScript {
  @Override
  protected void run() {
    init("26.0.0", "/mnt/data/Projects/Ghidra/logs/", "pvz2mapping_output.log");
    logHeader("Itanium Demangler", VERSION);

    Address startAddr = toAddr("00a7b1ac");
    Address endAddr = toAddr("00b142c5");

    while (startAddr.compareTo(endAddr) < 0) {
      String valueStr = Optional.ofNullable(listing.getDataAt(startAddr))
      .map(data -> {
        if (data.getDataType().getName() == "string") return data.getValue();
        return null;
      })
      .map(Object::toString)
      .orElse(null);

      if (valueStr != null) ItaniumUtil.demangle(valueStr);

      startAddr = startAddr.add(listing.getDataAt(startAddr).getLength());
    }
  }
}
