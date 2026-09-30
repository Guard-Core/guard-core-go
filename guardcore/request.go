package guardcore

import (
	"net/url"
	"strings"
	"sync"
	"time"
)

type BlockStash struct {
	Reason      string
	TriggerInfo string
}

type RequestState struct {
	ClientIP string
	// PipelineStartedAt is stamped by the Engine at dispatch and feeds
	// the reference's pipeline response_time on emitted events and
	// collected metrics.
	PipelineStartedAt time.Time
	ExclusionScoped   bool
	RouteUnresolved   bool
	IsWhitelisted     bool
	IsExempt          bool
	BypassChecks      []string
	BlockStash        *BlockStash
	Extras            map[string]any
	GuardRouteID      string
	RouteConfig       *RouteConfig
	AuthPrincipal     any
	bypassChecksOnce  sync.Once
	bypassSet         map[string]bool
}

func (s *RequestState) HasBypass(name string) bool {
	s.bypassChecksOnce.Do(func() {
		s.bypassSet = make(map[string]bool, len(s.BypassChecks))
		for _, b := range s.BypassChecks {
			s.bypassSet[b] = true
		}
	})
	return s.bypassSet[name] || s.bypassSet["all"]
}

type Headers struct{ m map[string]string }

func NewHeaders() Headers {
	return Headers{m: make(map[string]string)}
}

func HeadersFrom(values map[string]string) Headers {
	h := NewHeaders()
	for k, v := range values {
		h.Set(k, v)
	}
	return h
}

func (h Headers) Set(name, value string) { h.m[strings.ToLower(name)] = value }

func (h Headers) Get(name string) (string, bool) {
	v, ok := h.m[strings.ToLower(name)]
	return v, ok
}

func (h Headers) Delete(name string) { delete(h.m, strings.ToLower(name)) }

func (h Headers) Len() int { return len(h.m) }

func (h Headers) Map() map[string]string {
	out := make(map[string]string, len(h.m))
	for k, v := range h.m {
		out[k] = v
	}
	return out
}

type Request interface {
	URLPath() string
	URLScheme() string
	URLFull() string
	URLReplaceScheme(scheme string) string
	Method() string
	ClientHost() string
	Headers() Headers
	QueryParams() map[string]string
	Body() ([]byte, error)
	State() *RequestState
}

type RequestOptions struct {
	Path        string
	Scheme      string
	Host        string
	RawQuery    string
	Method      string
	ClientHost  string
	Header      map[string]string
	QueryParams map[string]string
	Body        []byte
	BodyFunc    func() ([]byte, error)
	State       *RequestState
}

type guardRequest struct {
	opts RequestOptions
	once sync.Once
	body []byte
	err  error
}

func (r *guardRequest) URLPath() string   { return r.opts.Path }
func (r *guardRequest) URLScheme() string { return r.opts.Scheme }
func (r *guardRequest) Method() string {
	if r.opts.Method == "" {
		return "GET"
	}
	return strings.ToUpper(r.opts.Method)
}
func (r *guardRequest) ClientHost() string { return r.opts.ClientHost }

func (r *guardRequest) URLFull() string {
	scheme := r.opts.Scheme
	if scheme == "" {
		scheme = "http"
	}
	full := scheme + "://" + r.opts.Host + r.opts.Path
	if r.opts.RawQuery != "" {
		full += "?" + r.opts.RawQuery
	}
	return full
}

func (r *guardRequest) URLReplaceScheme(scheme string) string {
	full := r.URLFull()
	if scheme == "" {
		return full
	}
	return scheme + "://" + strings.TrimPrefix(strings.TrimPrefix(full, "http://"), "https://")
}

func (r *guardRequest) Headers() Headers {
	if r.opts.Header == nil {
		return NewHeaders()
	}
	return HeadersFrom(r.opts.Header)
}

func (r *guardRequest) QueryParams() map[string]string {
	if r.opts.QueryParams != nil {
		return r.opts.QueryParams
	}
	if r.opts.RawQuery == "" {
		return map[string]string{}
	}
	values, err := url.ParseQuery(r.opts.RawQuery)
	if err != nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v[0]
	}
	return out
}

func (r *guardRequest) Body() ([]byte, error) {
	r.once.Do(func() {
		if r.opts.BodyFunc != nil {
			r.body, r.err = r.opts.BodyFunc()
			return
		}
		r.body = r.opts.Body
	})
	return r.body, r.err
}

func (r *guardRequest) State() *RequestState {
	if r.opts.State == nil {
		r.opts.State = &RequestState{}
	}
	return r.opts.State
}

type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

func (r *Response) SetHeader(name, value string) {
	if r.Headers == nil {
		r.Headers = make(map[string]string)
	}
	r.Headers[name] = value
}

type ResponseFactory struct{}

func NewResponseFactory() *ResponseFactory { return &ResponseFactory{} }

func (f *ResponseFactory) CreateResponse(content string, statusCode int) *Response {
	return &Response{StatusCode: statusCode, Headers: map[string]string{}, Body: []byte(content)}
}

func (f *ResponseFactory) CreateRedirectResponse(target string, statusCode int) *Response {
	resp := &Response{StatusCode: statusCode, Headers: map[string]string{}}
	resp.SetHeader("Location", target)
	return resp
}

type RequestFactory struct {
	Responses *ResponseFactory
}

func NewRequestFactory() *RequestFactory {
	return &RequestFactory{Responses: NewResponseFactory()}
}

func (f *RequestFactory) CreateRequest(opts RequestOptions) Request {
	return &guardRequest{opts: opts}
}
