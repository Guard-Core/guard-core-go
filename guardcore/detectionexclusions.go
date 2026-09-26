package guardcore

import "strings"

// Per-request detection exclusion resolution, the port of the _resolve_*
// helpers in guard_core/_utils/detection_config.py: every route surface
// overrides the global config when the route carries a non-nil value (the
// Python sentinel is None; the Go sentinel is nil), and the header
// exclusion set is additive (hardcoded defaults + config + route).

// routeDetectionExclusions is the resolved exclusion set for one request.
// enabledCategories is nil when every category scans (the reference passes
// None through to the scanners); scanBody defaults to true.
type routeDetectionExclusions struct {
	excludedParams     map[string]bool
	excludedBodyFields map[string]bool
	excludedHeaders    map[string]bool
	enabledCategories  map[string]bool
	scanBody           bool
}

func resolveDetectionExclusions(cfg *SecurityConfig, route *RouteConfig) routeDetectionExclusions {
	resolved := routeDetectionExclusions{
		excludedParams:     map[string]bool{},
		excludedBodyFields: map[string]bool{},
		excludedHeaders:    map[string]bool{},
		enabledCategories:  nil,
		scanBody:           true,
	}
	if cfg != nil {
		for name := range cfg.ExcludedDetectionParams {
			resolved.excludedParams[strings.ToLower(name)] = true
		}
		for name := range cfg.ExcludedDetectionBodyFields {
			resolved.excludedBodyFields[strings.ToLower(name)] = true
		}
		for _, category := range cfg.EnabledDetectionCategories {
			if resolved.enabledCategories == nil {
				resolved.enabledCategories = map[string]bool{}
			}
			resolved.enabledCategories[category] = true
		}
	}
	// The header set is a merge, never a replacement: the hardcoded proxy
	// identity defaults plus the configured set plus the route set
	// (_resolve_excluded_headers).
	for name := range DefaultExcludedHeaders {
		resolved.excludedHeaders[name] = true
	}
	if cfg != nil {
		for name := range cfg.ExcludedDetectionHeaders {
			resolved.excludedHeaders[strings.ToLower(name)] = true
		}
	}
	if route != nil {
		// _resolve_excluded_params / _resolve_excluded_body_fields: a
		// non-nil route set replaces the global one.
		if route.ExcludedDetectionParams != nil {
			resolved.excludedParams = map[string]bool{}
			for name := range route.ExcludedDetectionParams {
				resolved.excludedParams[strings.ToLower(name)] = true
			}
		}
		if route.ExcludedDetectionBodyFields != nil {
			resolved.excludedBodyFields = map[string]bool{}
			for name := range route.ExcludedDetectionBodyFields {
				resolved.excludedBodyFields[strings.ToLower(name)] = true
			}
		}
		if route.ExcludedDetectionHeaders != nil {
			for name := range route.ExcludedDetectionHeaders {
				resolved.excludedHeaders[strings.ToLower(name)] = true
			}
		}
		// _resolve_enabled_categories: a non-nil route set replaces the
		// global set (nil on the route keeps the global resolution, which
		// itself stays nil = all categories when nothing is configured).
		if route.EnabledDetectionCategories != nil {
			categories := map[string]bool{}
			for _, category := range route.EnabledDetectionCategories {
				categories[category] = true
			}
			resolved.enabledCategories = categories
		}
		// _resolve_scan_body: a non-nil route flag replaces the global
		// default of true.
		if route.DetectionScanBody != nil {
			resolved.scanBody = *route.DetectionScanBody
		} else if cfg != nil && cfg.DetectionScanBody != nil {
			resolved.scanBody = *cfg.DetectionScanBody
		}
	} else if cfg != nil && cfg.DetectionScanBody != nil {
		resolved.scanBody = *cfg.DetectionScanBody
	}
	return resolved
}
