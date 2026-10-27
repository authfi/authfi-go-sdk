package agent

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	dpop    *Key    // when set, tokens go as DPoP with a proof of this key
	nonces  *nonces // the nonces resources asked for, with dpop
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
		closeBody(req)
		return nil, ErrDestinationNotAllowed
	}
	tok, err := t.src.Token()
	if err != nil {
		closeBody(req)
		return nil, err
	}
	out := req.Clone(req.Context()) // a RoundTripper must not modify the caller's request
	for k := range out.Header {
		if strings.EqualFold(k, "x-api-key") || strings.EqualFold(k, "authorization") || strings.EqualFold(k, headerDPoP) {
			delete(out.Header, k) // a header set without canonical casing would otherwise survive
		}
	}
	if t.dpop == nil {
		out.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	} else if err := t.bindToKey(out, tok.AccessToken); err != nil {
		closeBody(req)
		return nil, err
	}
	if sc := trace.SpanContextFromContext(req.Context()); sc.IsValid() {
		if out.Header.Get("traceparent") == "" {
			out.Header.Set("traceparent", fmt.Sprintf("00-%s-%s-%s", sc.TraceID(), sc.SpanID(), sc.TraceFlags()))
		}
		if out.Header.Get("X-Request-Id") == "" {
			out.Header.Set("X-Request-Id", fmt.Sprintf("otel-%s-%s", sc.TraceID(), sc.SpanID()))
		}
	}
	resp, err := t.base.RoundTrip(out)
	if err != nil || t.dpop == nil {
		return resp, err
	}
	return t.retryWithNonce(req, out, resp, tok.AccessToken)
}

// bindToKey sets Authorization: DPoP and a proof of the transport's key for req.
func (t *transport) bindToKey(req *http.Request, token string) error {
	proof, err := t.dpop.dpopProof(req.Method, proofURL(req.URL), token, t.nonces.get(req.URL.Scheme+"://"+req.URL.Host), time.Now())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+token)
	req.Header.Set(headerDPoP, proof)
	return nil
}

// retryWithNonce remembers a nonce the resource sent and, when it refused for lack of one, sends the
// request once more with it. A request whose body cannot be replayed is not retried.
func (t *transport) retryWithNonce(orig, sent *http.Request, resp *http.Response, token string) (*http.Response, error) {
	nonce := resp.Header.Get(headerDPoPNonce)
	if nonce == "" {
		return resp, nil
	}
	origin := sent.URL.Scheme + "://" + sent.URL.Host
	had := t.nonces.get(origin)
	t.nonces.set(origin, nonce)
	if resp.StatusCode != http.StatusUnauthorized || nonce == had || (orig.Body != nil && orig.GetBody == nil) {
		return resp, nil
	}
	retry := orig.Clone(orig.Context())
	if orig.Body != nil {
		body, err := orig.GetBody()
		if err != nil {
			return resp, nil
		}
		retry.Body = body
	}
	for k := range retry.Header {
		if strings.EqualFold(k, "x-api-key") || strings.EqualFold(k, "authorization") || strings.EqualFold(k, headerDPoP) {
			delete(retry.Header, k)
		}
	}
	if err := t.bindToKey(retry, token); err != nil {
		return resp, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxReply))
	_ = resp.Body.Close()
	return t.base.RoundTrip(retry)
}

// closeBody closes a request body the transport will not send: RoundTripper must always close it.
func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}
