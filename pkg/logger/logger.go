// Package logger provides a unified logging interface using zap.
//
// It encapsulates zap configuration and provides a global logger
// with support for both development and production modes.
package logger

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// samplingTick is the time interval for sampling
	samplingTick = time.Second
	// samplingFirst is the number of messages to log in the first tick interval
	samplingFirst = 100
	// samplingThereafter is the number of messages to log after the first tick interval
	samplingThereafter = 100
)

var (
	// globalLogger is the global zap logger
	globalLogger *zap.Logger
	// globalSugar is the global sugared logger for printf-style logging
	globalSugar *zap.SugaredLogger
)

// Config holds logger configuration
type Config struct {
	Level           string // debug, info, warn, error
	Development     bool   // development mode with console output
	Encoding        string // json or console
	OutputPath      string // stdout, stderr, or file path
	SamplingEnabled bool   // enable sampling for high-frequency logs
}

// DefaultConfig returns default logger configuration
func DefaultConfig() Config {
	return Config{
		Level:       "info",
		Development: false,
		Encoding:    "json",
		OutputPath:  "stderr",
	}
}

// Initialize initializes the global logger with the given configuration
func Initialize(cfg Config) error {
	var zapConfig zap.Config

	if cfg.Development {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(parseLevel(cfg.Level))
		zapConfig.Encoding = cfg.Encoding
	} else {
		zapConfig = zap.NewProductionConfig()
		zapConfig.Level = zap.NewAtomicLevelAt(parseLevel(cfg.Level))
		zapConfig.Encoding = cfg.Encoding
		if cfg.OutputPath != "" {
			zapConfig.OutputPaths = []string{cfg.OutputPath}
		}
	}

	logger, err := zapConfig.Build()
	if err != nil {
		return err
	}

	// Add sampling for high-frequency logs if enabled
	if cfg.SamplingEnabled {
		logger = loggerWithOptions(logger, zap.WrapCore(func(core zapcore.Core) zapcore.Core {
			return zapcore.NewSamplerWithOptions(core, samplingTick, samplingFirst, samplingThereafter)
		}))
	}

	globalLogger = logger
	globalSugar = logger.Sugar()
	return nil
}

// loggerWithOptions applies options to a logger
func loggerWithOptions(logger *zap.Logger, opts ...zap.Option) *zap.Logger {
	return logger.WithOptions(opts...)
}

// parseLevel converts string level to zapcore.Level
func parseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "info":
		return zapcore.InfoLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

// L returns the global zap Logger
func L() *zap.Logger {
	if globalLogger == nil {
		// Fallback to no-op logger if not initialized
		return zap.NewNop()
	}
	return globalLogger
}

// S returns the global SugaredLogger for printf-style logging
func S() *zap.SugaredLogger {
	if globalSugar == nil {
		// Fallback to no-op logger if not initialized
		return zap.NewNop().Sugar()
	}
	return globalSugar
}

// Sync flushes any buffered log entries
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// ReplaceGlobals replaces the global logger and returns a function to restore the original
func ReplaceGlobals(logger *zap.Logger) func() {
	prev := globalLogger
	globalLogger = logger
	globalSugar = logger.Sugar()
	return func() {
		ReplaceGlobals(prev)
	}
}

// InitDevelopment initializes logger in development mode
func InitDevelopment() error {
	cfg := DefaultConfig()
	cfg.Development = true
	cfg.Level = "debug"
	cfg.Encoding = "console"
	return Initialize(cfg)
}

// InitProduction initializes logger in production mode
func InitProduction() error {
	cfg := DefaultConfig()
	cfg.Development = false
	cfg.Level = "info"
	cfg.Encoding = "json"
	return Initialize(cfg)
}

// InitWithLevel initializes logger with specified level
func InitWithLevel(level string) error {
	cfg := DefaultConfig()
	cfg.Level = level
	return Initialize(cfg)
}

// StdLogger returns a standard library logger that writes to zap
func StdLogger() *zap.Logger {
	return L()
}

// Named returns a named child logger according to zap best practices
// This allows for better log organization and filtering by component
func Named(name string) *zap.Logger {
	if globalLogger == nil {
		return zap.NewNop().Named(name)
	}
	return globalLogger.Named(name)
}

// With returns a logger with additional fields added according to zap best practices
// This allows for adding context to loggers that will be included in all log entries
func With(fields ...zap.Field) *zap.Logger {
	if globalLogger == nil {
		return zap.NewNop().With(fields...)
	}
	return globalLogger.With(fields...)
}
