package guardcore

import "log"

// applyModifier mirrors the reference response factory's apply_modifier
// (guard_core/core/responses/factory.py): when the config carries a
// custom_response_modifier the callback runs over the response and its
// result replaces it. A panic inside the callback is contained the way
// the reference contains an exception: the engine logs
// "custom_response_modifier raised ...; returning unmodified response"
// and hands back the incoming response. A nil result also keeps the
// incoming response (the reference Callable type cannot return None; Go
// can, and reading nil as "drop the block" would silently un-block).
func applyModifier(cfg *SecurityConfig, response *Response) *Response {
	if cfg == nil || cfg.CustomResponseModifier == nil {
		return response
	}
	result, panicked := runResponseModifier(cfg.CustomResponseModifier, response)
	if panicked || result == nil {
		return response
	}
	return result
}

// runResponseModifier invokes the callback with the reference containment:
// a panic is logged with the reference's message and reported so the
// caller returns the unmodified response.
func runResponseModifier(modifier func(*Response) *Response, response *Response) (result *Response, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("custom_response_modifier raised: %v; returning unmodified response", r)
			panicked = true
		}
	}()
	return modifier(response), false
}
