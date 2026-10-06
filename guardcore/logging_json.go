package guardcore

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Structured logging, ported from the reference
// guard_core/_utils/logging_utils.py (JsonFormatter + setup_custom_logging):
// log_format="json" emits one JSON object per line
// ({"timestamp","level","logger","message"}), the text format keeps the
// reference's "[guardcore] asctime - LEVEL - message" line, and an optional
// log file receives the same stream (directories are created on demand, a
// failing file path falls back to console-only with a warning).

// ValidLogFormats enumerates the log_format config surface.
var ValidLogFormats = map[string]bool{"text": true, "json": true}

// JsonFormatter renders one record as the reference's JSON line
// (logging_utils.JsonFormatter.format): timestamp, level, logger, message.
type JsonFormatter struct {
	// TimeNow is injectable for tests; nil uses time.Now.
	TimeNow func() time.Time
}

// Format renders one record. The timestamp keeps Python's asctime shape
// ("2006-01-02 15:04:05,mmm"), the level is the process-level INFO the
// engine logs at (the stdlib log carries no per-record level), and the
// logger name is the Go counterpart of the "guard_core" logger.
func (f JsonFormatter) Format(message string) string {
	return formatJSONRecord(f.timestamp(), "INFO", guardLoggerName, message)
}

func (f JsonFormatter) timestamp() string {
	now := time.Now
	if f.TimeNow != nil {
		now = f.TimeNow
	}
	return now().Format("2006-01-02 15:04:05.000")
}

func formatJSONRecord(timestamp, level, loggerName, message string) string {
	entry := map[string]string{
		"timestamp": timestamp,
		"level":     level,
		"logger":    loggerName,
		"message":   message,
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		// json.Marshal over a string map cannot fail; the fallback keeps
		// the record lossless anyway.
		return fmt.Sprintf(`{"timestamp":%q,"level":%q,"logger":%q,"message":%q}`,
			timestamp, level, loggerName, message)
	}
	return string(encoded)
}

// guardLoggerName is the Go counterpart of the reference's
// logging.getLogger("guard_core") logger name.
const guardLoggerName = "guardcore"

// textFormatRecord mirrors _create_formatter's text branch:
// "[%(name)s] %(asctime)s - %(levelname)s - %(message)s".
func textFormatRecord(timestamp, level, loggerName, message string) string {
	return fmt.Sprintf("[%s] %s - %s - %s", loggerName, timestamp, level, message)
}

// recordFormatter is the formatter seam over the two formats.
type recordFormatter func(timestamp, message string) string

func formatterFor(logFormat string) recordFormatter {
	if logFormat == "json" {
		return func(_, message string) string {
			return JsonFormatter{}.Format(message)
		}
	}
	return func(timestamp, message string) string {
		return textFormatRecord(timestamp, "INFO", guardLoggerName, message)
	}
}

// recordWriter adapts the stdlib logger's single-write-per-record output
// into the formatted record stream.
type recordWriter struct {
	out       io.Writer
	formatter recordFormatter
	mu        sync.Mutex
}

func (w *recordWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	message := strings.TrimRight(string(p), "\n")
	stamp := time.Now().Format("2006-01-02 15:04:05.000")
	formatted := w.formatter(stamp, message)
	if _, err := fmt.Fprintln(w.out, formatted); err != nil {
		return 0, err
	}
	return len(p), nil
}

// customLogging owns the handlers SetupCustomLogging installed. A second
// call replaces them (closing the previous file) exactly like the
// reference removes its own handlers before re-adding; the standard
// writer captured before the first install restores with
// restoreStandardLogging (the Go escape hatch for the reference's
// handler removal).
var customLogging struct {
	mu         sync.Mutex
	installed  bool
	file       *os.File
	prevWriter io.Writer
	prevFlags  int
}

// customLogConsole is the console sink (the reference StreamHandler);
// tests swap it.
var customLogConsole io.Writer = os.Stderr

// SetupCustomLogging mirrors setup_custom_logging(log_file, log_format):
// it (re)installs the guardcore log stream in the requested format on
// the package default logger every engine component logs through, adds a
// file handler when logFile is set (creating directories on demand,
// falling back to console-only with a warning on failure), and returns
// the logger. The reference's _YieldToHostRootHandlers filter has no
// stdlib equivalent: installing here redirects the process default
// logger, so hosts that share log.Default() should instead take the
// returned logger and inject it explicitly.
func SetupCustomLogging(logFile, logFormat string) *log.Logger {
	customLogging.mu.Lock()
	defer customLogging.mu.Unlock()

	formatter := formatterFor(logFormat)

	if !customLogging.installed {
		customLogging.prevWriter = log.Default().Writer()
		customLogging.prevFlags = log.Flags()
		log.SetFlags(0)
	} else if customLogging.file != nil {
		_ = customLogging.file.Close()
		customLogging.file = nil
	}

	console := &recordWriter{out: customLogConsole, formatter: formatter}
	if logFile == "" {
		log.SetOutput(console)
		customLogging.installed = true
		return log.Default()
	}

	dir := filepath.Dir(logFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("Failed to create log file %s: %v", logFile, err)
			log.SetOutput(console)
			customLogging.installed = true
			return log.Default()
		}
	}
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("Failed to create log file %s: %v", logFile, err)
		log.SetOutput(console)
		customLogging.installed = true
		return log.Default()
	}
	customLogging.file = file
	// The reference adds both handlers: console and file each see every
	// record. One writer fans out to both sinks.
	log.SetOutput(&recordWriter{out: io.MultiWriter(customLogConsole, file), formatter: formatter})
	customLogging.installed = true
	return log.Default()
}

// restoreStandardLogging puts the process default logger back the way it
// was before the first SetupCustomLogging call (the test and host-app
// escape hatch; the reference has no counterpart because Python's named
// logger is not the process default).
func restoreStandardLogging() {
	customLogging.mu.Lock()
	defer customLogging.mu.Unlock()
	if !customLogging.installed {
		return
	}
	if customLogging.file != nil {
		_ = customLogging.file.Close()
		customLogging.file = nil
	}
	log.SetOutput(customLogging.prevWriter)
	log.SetFlags(customLogging.prevFlags)
	customLogging.installed = false
}
