package agent

import (
	"fmt"
	"regexp"
	"strings"
)

// The names the AuthFI gateway uses on a tools/call result and on a held call.
const (
	// ApprovalArgument is the argument a held call is sent again with, naming the approval a
	// person gave. Never show a model the value.
	ApprovalArgument = "_authfi_approval_id"
	// RefusalMeta is the _meta key of a refused call's detail.
	RefusalMeta = "io.authfi/refusal"
	// HoldMessage is what a model may be told about a held call: the wait, never an id.
	HoldMessage = "This action is waiting for a person's approval."
)

// ToolResult is the part of an MCP tools/call result that matters here. Copy it from the MCP
// client's CallToolResult: IsError, the text content joined, and the result's _meta.
type ToolResult struct {
	IsError bool
	Text    string
	Meta    map[string]any
}

// OutcomeKind says what the gateway did with a call.
type OutcomeKind string

const (
	// Result is the tool's own answer.
	Result OutcomeKind = "result"
	// Refused means the gateway refused the call; Code, Reason and RequiredScope say why.
	Refused OutcomeKind = "refused"
	// Held means a person must approve; ApprovalID names the approval.
	Held OutcomeKind = "held"
)

// Outcome is what ReadResult found.
type Outcome struct {
	Kind          OutcomeKind
	Text          string // the tool's own text, for a Result
	Code          string
	Reason        string
	RequiredScope string
	ApprovalID    string
}

// ModelText is what a model may read about this outcome. For a hold it is the wait, with no id;
// for a refusal it is the code and the reason, with no id.
func (o Outcome) ModelText() string {
	switch o.Kind {
	case Held:
		return HoldMessage
	case Refused:
		text := "Refused by AuthFI"
		if o.Code != "" {
			text += " (" + o.Code + ")"
		}
		if o.Reason != "" {
			text += ": " + o.Reason
		}
		text += "."
		if o.RequiredScope != "" {
			text += " The call needs the scope " + o.RequiredScope + "."
		}
		return text
	}
	return o.Text
}

// holdText matches the gateway's hold message at the start of an error result: the id, then the
// "(code)" or the "A person must approve" that the gateway always writes. Either one is enough, so a
// change of wording around the id still reads as a hold, while an unrelated error that starts with
// the same three words ("Waiting for approval from your manager timed out") does not. Case is not
// significant and punctuation after the id is not part of it.
var holdText = regexp.MustCompile(`(?i)^\s*waiting\s+for\s+approval\s+([^\s()]+?)[.,;:]?\s*(?:\(([a-z_]+)\)|\.?\s*a\s+person\s+must\s+approve)`)

// ReadResult reads one tools/call result. Only an error result can be a refusal or a hold, so a
// tool whose output quotes the gateway's words is still its own answer. A refusal is read from
// _meta["io.authfi/refusal"]; a hold from the gateway's message.
func ReadResult(r ToolResult) Outcome {
	if !r.IsError {
		return Outcome{Kind: Result, Text: r.Text}
	}
	if detail, ok := r.Meta[RefusalMeta].(map[string]any); ok {
		id := str(detail, "approval_id")
		reason := firstNonEmpty(str(detail, "reason"), str(detail, "error"))
		code := str(detail, "code")
		if id != "" {
			hide := regexp.MustCompile("(?i)" + regexp.QuoteMeta(id))
			reason, code = hide.ReplaceAllString(reason, "[approval]"), hide.ReplaceAllString(code, "[approval]")
		}
		return Outcome{
			Kind:          Refused,
			Code:          code,
			Reason:        reason,
			RequiredScope: str(detail, "required_scope"),
			ApprovalID:    id,
		}
	}
	if m := holdText.FindStringSubmatch(strings.TrimSpace(r.Text)); m != nil {
		return Outcome{Kind: Held, ApprovalID: m[1], Code: m[2]}
	}
	return Outcome{Kind: Result, Text: r.Text}
}

// WithApproval returns a copy of arguments that carries the approval a held call waited for.
func WithApproval(arguments map[string]any, approvalID string) (map[string]any, error) {
	if approvalID == "" {
		return nil, fmt.Errorf("agent: the approval id is required")
	}
	out := make(map[string]any, len(arguments)+1)
	for k, v := range arguments {
		out[k] = v
	}
	out[ApprovalArgument] = approvalID
	return out, nil
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
