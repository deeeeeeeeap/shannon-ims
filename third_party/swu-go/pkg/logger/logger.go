package logger

import (
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	globalLogger *zap.Logger
	globalSugar  *zap.SugaredLogger
	once         sync.Once
)

// fixedWidthColorLevelEncoder 固定宽度（5字符）的彩色日志等级编码器
func fixedWidthColorLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	// 日志等级固定 5 字符宽度：DEBUG, INFO_, WARN_, ERROR, FATAL
	s := level.CapitalString()
	for len(s) < 5 {
		s += " "
	}
	// 添加颜色
	switch level {
	case zapcore.DebugLevel:
		s = "\x1b[35m" + s + "\x1b[0m" // 紫色
	case zapcore.InfoLevel:
		s = "\x1b[34m" + s + "\x1b[0m" // 蓝色
	case zapcore.WarnLevel:
		s = "\x1b[33m" + s + "\x1b[0m" // 黄色
	case zapcore.ErrorLevel:
		s = "\x1b[31m" + s + "\x1b[0m" // 红色
	case zapcore.FatalLevel, zapcore.PanicLevel, zapcore.DPanicLevel:
		s = "\x1b[31;1m" + s + "\x1b[0m" // 红色加粗
	}
	enc.AppendString(s)
}

// Init 初始化全局日志器
// level: debug, info, warn, error
// format: json, console
func Init(level, format string) error {
	var err error
	once.Do(func() {
		err = initLogger(level, format)
	})
	return err
}

func initLogger(level, format string) error {
	// 解析日志级别
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	// 配置编码器
	var encoderConfig zapcore.EncoderConfig
	if format == "json" {
		encoderConfig = zap.NewProductionEncoderConfig()
	} else {
		encoderConfig = zap.NewDevelopmentEncoderConfig()
		encoderConfig.EncodeLevel = fixedWidthColorLevelEncoder
		encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("[2006-01-02 15:04:05]")
		encoderConfig.EncodeCaller = func(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
			const width = 28
			s := caller.TrimmedPath()
			if len(s) < width {
				s += strings.Repeat(" ", width-len(s))
			}
			enc.AppendString(s)
		}
		encoderConfig.ConsoleSeparator = " "
	}
	encoderConfig.TimeKey = "time"
	if format == "json" {
		encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// 创建编码器
	var encoder zapcore.Encoder
	if format == "json" {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	} else {
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	}

	// 创建核心
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(os.Stdout),
		zapLevel,
	)

	// 创建 Logger
	globalLogger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	globalSugar = globalLogger.Sugar()

	return nil
}

// SetLogger 设置外部 Logger（允许主应用注入自己的 logger）
func SetLogger(l *zap.Logger) {
	globalLogger = l
	globalSugar = l.Sugar()
}

// Get 获取全局 Logger
func Get() *zap.Logger {
	if globalLogger == nil {
		Init("info", "console")
	}
	return globalLogger
}

// Sugar 获取 SugaredLogger
func Sugar() *zap.SugaredLogger {
	if globalSugar == nil {
		Init("info", "console")
	}
	return globalSugar
}

// Sync 刷新日志缓冲
func Sync() {
	if globalLogger != nil {
		done := make(chan struct{})
		go func() {
			_ = globalLogger.Sync()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// 便捷方法

// Debug 记录调试信息
func Debug(msg string, fields ...zap.Field) {
	Get().WithOptions(zap.AddCallerSkip(1)).Debug(msg, fields...)
}

// Info 记录信息
func Info(msg string, fields ...zap.Field) {
	Get().WithOptions(zap.AddCallerSkip(1)).Info(msg, fields...)
}

// Warn 记录警告
func Warn(msg string, fields ...zap.Field) {
	Get().WithOptions(zap.AddCallerSkip(1)).Warn(msg, fields...)
}

// Error 记录错误
func Error(msg string, fields ...zap.Field) {
	Get().WithOptions(zap.AddCallerSkip(1)).Error(msg, fields...)
}

// Fatal 记录致命错误并退出
func Fatal(msg string, fields ...zap.Field) {
	Get().WithOptions(zap.AddCallerSkip(1)).Fatal(msg, fields...)
}

// With 创建带字段的 Logger
func With(fields ...zap.Field) *zap.Logger {
	return Get().With(fields...)
}

// Named 创建命名 Logger
func Named(name string) *zap.Logger {
	return Get().Named(name)
}

// 便捷字段函数 (从 zap 导出)
var (
	String   = zap.String
	Int      = zap.Int
	Int64    = zap.Int64
	Uint32   = zap.Uint32
	Uint64   = zap.Uint64
	Float64  = zap.Float64
	Bool     = zap.Bool
	Duration = zap.Duration
	Time     = zap.Time
	Err      = zap.Error
	Any      = zap.Any
	Binary   = zap.Binary
)
