package com.sad.pvz2;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import ghidra.app.script.GhidraScript;

/**
 * Helper class for logging messages in the Ghidra Console and log files
 */
public class ScriptLogger {
  public static Path LOG_FILE_PATH;
  public static GhidraScript SCRIPT;

  public static void init(GhidraScript script, String filePath, String fileName) {
    ScriptLogger.SCRIPT = script;
    ScriptLogger.LOG_FILE_PATH = Paths.get(filePath, fileName);
  }

  public static void logHeader(String header) {
    log("╔══════════════════════════════════════════╗", false);
    log("║ " + header + " Log from " + DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now()) + " ║", false);
    log("╚══════════════════════════════════════════╝\n", false);
  }

  public static void log(String message, boolean inConsole) {
    if (inConsole) SCRIPT.println(message);
    writeLogFile(message + System.lineSeparator());
  }

  public static void log(String message) {
    log(message, true);
  }

  public static void error(String message, Exception err) {
    SCRIPT.printerr(message + err.getMessage());
    writeLogFile("[ERROR] " + message + System.lineSeparator() + err.getMessage() + System.lineSeparator());
  }

  public static void writeLogFile(String message) {
    try {
      if (LOG_FILE_PATH.getParent() != null) {
        Files.createDirectories(LOG_FILE_PATH.getParent());
      }
      Files.writeString(LOG_FILE_PATH, message, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
    catch (IOException e) {
      SCRIPT.printerr("Failed to write to log file: " + e.getMessage());
    }
  }
}
