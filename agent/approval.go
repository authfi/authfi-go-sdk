package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	authfi "github.com/authfi/authfi-go-sdk"
)

// ErrApprovalStatusNotOffered means the project does not let an agent read its own approvals. Wait
// by sending the held call again instead (see ReadResult).
var ErrApprovalStatusNotOffered = errors.New("agent: this project does not offer approval status to agents")

// Approval is a person's decision on one action, as the platform reports it.
type Approval struct {
	ID         string
	Status     string // pending, approved, denied or expired
	Action     string
	CreatedAt  string
	ExpiresAt  string
	ResolvedAt string
}

// Pending reports whether nobody has decided yet.
func (p Approval) Pending() bool { return p.Status == "" || p.Status == "pending" }

// ApprovalStatus reads approval id with the agent's own token.
func (a *Agent) ApprovalStatus(ctx context.Context, id string) (Approval, error) {
	if strings.TrimSpace(id) == "" || id == "." || id == ".." {
		return Approval{}, errors.New("agent: the approval id is required")
	}
	ep, err := a.endpoints(ctx)
	if err != nil {
		return Approval{}, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(err.Error()), Err: err}
	}
	if ep.approval == "" && ep.configErr != nil {
		return Approval{}, &TokenError{Code: "discovery_failed", Description: authfi.Scrub(ep.configErr.Error()), Err: ep.configErr}
	}
	if ep.approval == "" || !strings.Contains(ep.approval, "{id}") {
		return Approval{}, ErrApprovalStatusNotOffered
	}
	tok, err := a.Token(ctx)
	if err != nil {
		return Approval{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.Replace(ep.approval, "{id}", url.PathEscape(id), 1), nil)
	if err != nil {
		return Approval{}, errors.New("agent: bad approval URL")
	}
	req.Header.Set("Authorization", "Bearer "+tok.Reveal())
	r, err := a.do(req)
	if err != nil {
		return Approval{}, &TokenError{Code: "unreachable", Description: authfi.Scrub(err.Error(), tok.Reveal()), Err: err}
	}
	if r.status == http.StatusForbidden {
		return Approval{}, ErrApprovalStatusNotOffered
	}
	if r.status != http.StatusOK {
		return Approval{}, tokenFailure(r.status, r.body, tok.Reveal())
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	body := r.body
	if json.Unmarshal(body, &env) == nil && len(env.Data) > 0 && env.Data[0] == '{' {
		body = env.Data
	}
	var d struct {
		ID         string `json:"approval_id"`
		Status     string `json:"status"`
		Action     string `json:"requesting_action"`
		CreatedAt  string `json:"created_at"`
		ExpiresAt  string `json:"expires_at"`
		ResolvedAt string `json:"resolved_at"`
	}
	if json.Unmarshal(body, &d) != nil || d.ID == "" {
		return Approval{}, &TokenError{Code: "invalid_response", Description: "the approval endpoint answered no approval_id", Status: r.status}
	}
	return Approval{ID: d.ID, Status: d.Status, Action: d.Action, CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt, ResolvedAt: d.ResolvedAt}, nil
}

// WaitForApproval polls ApprovalStatus every interval (default 3 s) until a person decides, and
// returns the decision whatever it is. A cancelled ctx stops the wait and leaves the approval open.
func (a *Agent) WaitForApproval(ctx context.Context, id string, interval time.Duration) (Approval, error) {
	if interval <= 0 {
		interval = 3 * time.Second
	}
	for {
		ap, err := a.ApprovalStatus(ctx, id)
		if err != nil {
			return Approval{}, err
		}
		if !ap.Pending() {
			return ap, nil
		}
		if err := a.sleep(ctx, interval); err != nil {
			return Approval{}, err
		}
	}
}
