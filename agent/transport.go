package agent

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

// ErrDestinationNotAllowed is returned when a request is for an origin the token may not be sent
// to. The request is not sent.
var ErrDestinationNotAllowed = errors.New("agent: the token may not be sent to this destination")

type transport struct {
	src     oauth2.TokenSource
	base    http.RoundTripper
	origins map[string]bool
}

// Transport returns an http.RoundTripper that puts the current token of src on every request as
// Authorization: Bearer, removes any x-api-key header (a leftover key from a framework's own
// configuration would otherwise beat the token), and stamps X-Request-Id and traceparent from the
// OpenTelemetry span in the request context so the gateway's call record joins the caller's trace.
//
// sendTo lists the origins (scheme://host[:port]) the token may go to; it is required, and a
// request to any other origin, including one reached by a redirect, fails with
// ErrDestinationNotAllowed before anything is sent. Use it as the Transport of the http.Client
// given to the Anthropic Go SDK, LangChainGo or the MCP Go SDK. src is Agent.TokenSource() or
// DelegatedToken.TokenSource().
func Transport(src oauth2.TokenSource, base http.RoundTripper, sendTo ...string) (http.RoundTripper, error) {
	if src == nil {
		return nil, errors.New("agent: a token source is required")
	}
	if len(sendTo) == 0 {
		return nil, errors.New("agent: sendTo is required: name the origins the token may go to")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	origins := make(map[string]bool, len(sendTo))
	for _, o := range sendTo {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || checkOrigin(strings.TrimRight(o, "/")) != nil {
			return nil, fmt.Errorf("agent: sendTo %q is not an https origin", o)
		}
		origins[u.Scheme+"://"+u.Host] = true
	}
	return &transport{src: src, base: base, origins: origins}, nil
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.origins[req.URL.Scheme+"://"+req.URL.Host] {
		return nil, ErrDestinationNotAllowed
	}
	tok, err := t.src.Token()
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context()) // a RoundTripper must not modify the caller's request
	out.Header.Del("X-Api-Key")
	out.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	if sc := trace.SpanContextFromContext(req.Context()); sc.IsValid() {
		if out.Header.Get("traceparent") == "" {
			out.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-%s", sc.TraceID(), sc.SpanID(), sc.TraceFlags()))
		}
		if out.Header.Get("X-Request-Id") == "" {
			out.Header.Set("X-Request-Id", fmt.Sprintf("otel-%s-%s", sc.TraceID(), sc.SpanID()))
		}
	}
	return t.base.RoundTrip(out)
}
