package com.sad.pvz2;

import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Helper class for logging messages in the Ghidra Console and log files
 */
public class ScriptLogger {
  public static Path LOG_FILE_PATH;
  public static PvZ2BaseScript SCRIPT;
  public static int WIDTH = 56;

  public static void init(PvZ2BaseScript script, String filePath, String fileName) {
    ScriptLogger.SCRIPT = script;
    ScriptLogger.LOG_FILE_PATH = Paths.get(filePath, fileName);
  }

  public static void logHeader(String scriptName, String version, String gameVersion) {
    String scriptLine = scriptName + " Log v" + version;
    String gameLine = "Game Version: " + gameVersion;
    String timestamp = "Timestamp: " + DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").format(LocalDateTime.now());

    log("╔" + "═".repeat(WIDTH)             + "╗", false);
    log("║" + centerText(scriptLine) + "║", false);
    log("║" + centerText(gameLine)   + "║", false);
    log("║" + centerText(timestamp)  + "║", false);
    log("╚" + "═".repeat(WIDTH)             + "╝", false);
  }

  private static String centerText(String text) {
    if (text.length() >= WIDTH) return text.substring(0, WIDTH); // Truncate if too long
    int totalPadding = WIDTH - text.length();
    int leftPadding = totalPadding / 2;
    int rightPadding = totalPadding - leftPadding;

    return " ".repeat(leftPadding) + text + " ".repeat(rightPadding);
  }

  public static void divider() {
    log("━".repeat(WIDTH), false);
  }

  public static void log(String message, boolean inConsole) {
    if (inConsole) SCRIPT.println(message);
    writeLogFile(message + System.lineSeparator());
  }

  public static void log(String message) {
    log(message, true);
  }

  public static void warn(String message) {
    SCRIPT.printerr(message);
    writeLogFile("[WARN] " + message + System.lineSeparator());
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
