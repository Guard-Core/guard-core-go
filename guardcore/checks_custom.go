package guardcore

import (
	"log"
	"reflect"
	"runtime"
	"strings"
)

type requestLoggingCheck struct {
	cfg    *SecurityConfig
	logger *log.Logger
}

func (c *requestLoggingCheck) CheckName() string             { return "request_logging" }
func (c *requestLoggingCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *requestLoggingCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cfg.LogRequestLevel != ""
}

func (c *requestLoggingCheck) Check(req Request) *Response {
	LogActivity(req, LogOptions{
		Logger:              c.logger,
		LogType:             "request",
		Level:               c.cfg.LogRequestLevel,
		CheckName:           c.CheckName(),
		MutedCheckLogs:      c.cfg.MutedCheckLogs,
		SensitiveHeaders:    c.cfg.LogSensitiveHeaders,
		SensitiveParams:     c.cfg.LogSensitiveParams,
		SensitiveBodyFields: c.cfg.LogSensitiveBodyFields,
	})
	return nil
}

type customValidatorsCheck struct {
	cfg    *SecurityConfig
	logger *log.Logger
	routes []*RouteConfig
}

func (c *customValidatorsCheck) CheckName() string             { return "custom_validators" }
func (c *customValidatorsCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *customValidatorsCheck) AppliesTo(cfg *SecurityConfig) bool {
	if cfg == nil {
		return false
	}
	return customValidatorsApplies(c.routes)
}

func customValidatorsApplies(routes []*RouteConfig) bool {
	return anyRoute(routes, func(rc *RouteConfig) bool { return len(rc.CustomValidators) > 0 })
}

func (c *customValidatorsCheck) Check(req Request) *Response {
	routeConfig := req.State().RouteConfig
	if routeConfig == nil || len(routeConfig.CustomValidators) == 0 {
		return nil
	}
	cfg := c.cfg
	for _, validator := range routeConfig.CustomValidators {
		validationResponse := validator(req)
		if validationResponse == nil {
			continue
		}
		LogActivity(req, LogOptions{
			Logger:              c.logger,
			LogType:             "suspicious",
			Reason:              "Custom validation failed",
			Level:               cfg.LogSuspiciousLevel,
			PassiveMode:         cfg.PassiveMode,
			CheckName:           c.CheckName(),
			MutedCheckLogs:      cfg.MutedCheckLogs,
			OnBlock:             cfg.OnBlock,
			SensitiveHeaders:    cfg.LogSensitiveHeaders,
			SensitiveParams:     cfg.LogSensitiveParams,
			SensitiveBodyFields: cfg.LogSensitiveBodyFields,
		})
		// Reference custom_validators.py: decorator_violation,
		// decorator_type content_filtering, violation_type
		// custom_validation.
		emitAccessDeniedEvent(cfg, req, "Custom validation failed", "content_filtering", cfg.PassiveMode,
			map[string]any{"violation_type": "custom_validation"})
		if !cfg.PassiveMode {
			fireBlockHook(cfg, req, c.CheckName(), "Custom validation failed", "custom_validation", false, validationResponse.StatusCode)
			return validationResponse
		}
	}
	return nil
}

type customRequestCheck struct {
	cfg    *SecurityConfig
	logger *log.Logger
}

func (c *customRequestCheck) CheckName() string             { return "custom_request" }
func (c *customRequestCheck) EnforcedOnExcludedPaths() bool { return false }
func (c *customRequestCheck) AppliesTo(cfg *SecurityConfig) bool {
	return cfg != nil && cfg.CustomRequestCheck != nil
}

func (c *customRequestCheck) Check(req Request) *Response {
	if c.cfg.CustomRequestCheck == nil {
		return nil
	}
	customResponse := c.cfg.CustomRequestCheck(req)
	if customResponse == nil {
		return nil
	}
	// Reference custom_request.py: custom_request_check with the blocking
	// response's status and the check function's name (anonymous when it
	// has none).
	emitBusEvent(c.cfg, EventCustomRequestCheck, req, blockedOrLoggedAction(c.cfg.PassiveMode),
		"Custom request check returned blocking response",
		map[string]any{
			"response_status": blockHookStatusCode(customResponse.StatusCode),
			"check_function":  customRequestCheckFunctionName(c.cfg.CustomRequestCheck, c.cfg.CustomRequestCheckName),
		})
	if c.cfg.PassiveMode {
		return nil
	}
	return customResponse
}

// customRequestCheckFunctionName mirrors custom_request.py's
// check_function kwarg: the configured CustomRequestCheckName when the
// adapter named its check (the reference __name__ has no Go identifier
// equivalent), else the function's bare runtime name, "anonymous" when
// the value carries none.
func customRequestCheckFunctionName(fn func(Request) *Response, configuredName string) string {
	if configuredName != "" {
		return configuredName
	}
	full := runtime.FuncForPC(reflect.ValueOf(fn).Pointer()).Name()
	if full == "" {
		return "anonymous"
	}
	name := full
	if idx := strings.LastIndexByte(name, '/'); idx != -1 {
		name = name[idx+1:]
	}
	if idx := strings.LastIndexByte(name, '.'); idx != -1 {
		name = name[idx+1:]
	}
	if name == "" {
		return "anonymous"
	}
	return name
}
