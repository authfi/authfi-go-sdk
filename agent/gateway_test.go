package agent

import (
	"strings"
	"testing"
)

func TestReadResultAnswers(t *testing.T) {
	cases := []struct {
		name string
		in   ToolResult
		want Outcome
	}{
		{"plain result", ToolResult{Text: "42 rows"}, Outcome{Kind: Result, Text: "42 rows"}},
		{"refusal from _meta", ToolResult{IsError: true, Text: "denied", Meta: map[string]any{RefusalMeta: map[string]any{
			"code": "mcp_scope_missing", "reason": "the agent may not refund", "required_scope": "orders:refund"}}},
			Outcome{Kind: Refused, Code: "mcp_scope_missing", Reason: "the agent may not refund", RequiredScope: "orders:refund"}},
		{"refusal falls back to error text", ToolResult{IsError: true, Meta: map[string]any{RefusalMeta: map[string]any{"code": "c", "error": "e"}}},
			Outcome{Kind: Refused, Code: "c", Reason: "e"}},
		{"hold", ToolResult{IsError: true, Text: "Waiting for approval apr_123 (approval_required). A person must approve this action in the AuthFI console. Retry with _authfi_approval_id."},
			Outcome{Kind: Held, ApprovalID: "apr_123", Code: "approval_required"}},
		{"a tool that quotes the hold text is still its answer", ToolResult{Text: "Waiting for approval apr_123 (approval_required). A person must approve this action"},
			Outcome{Kind: Result, Text: "Waiting for approval apr_123 (approval_required). A person must approve this action"}},
		{"a tool that quotes _meta without an error is its answer", ToolResult{Text: "x", Meta: map[string]any{RefusalMeta: map[string]any{"code": "c"}}},
			Outcome{Kind: Result, Text: "x"}},
		{"hold text not at the start is not a hold", ToolResult{IsError: true, Text: "Note: Waiting for approval apr_1 (approval_required). A person must approve this action"},
			Outcome{Kind: Result, Text: "Note: Waiting for approval apr_1 (approval_required). A person must approve this action"}},
		{"an ordinary tool error", ToolResult{IsError: true, Text: "disk full"}, Outcome{Kind: Result, Text: "disk full"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReadResult(tc.in); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestModelTextNeverCarriesTheApprovalID(t *testing.T) {
	held := ReadResult(ToolResult{IsError: true, Text: "Waiting for approval apr_SECRET (approval_required). A person must approve this action"})
	if held.ModelText() != HoldMessage || strings.Contains(held.ModelText(), "apr_SECRET") {
		t.Fatalf("%q", held.ModelText())
	}
	refused := Outcome{Kind: Refused, Code: "c", Reason: "no", RequiredScope: "s", ApprovalID: "apr_SECRET"}
	got := refused.ModelText()
	if strings.Contains(got, "apr_SECRET") || !strings.Contains(got, "(c)") || !strings.Contains(got, "no") || !strings.Contains(got, "scope s") {
		t.Fatalf("%q", got)
	}
	if (Outcome{Kind: Result, Text: "hi"}).ModelText() != "hi" {
		t.Fatal("a result reads as itself")
	}
}

func TestWithApprovalCopies(t *testing.T) {
	orig := map[string]any{"order": 4411}
	got, err := WithApproval(orig, "apr_1")
	if err != nil || got[ApprovalArgument] != "apr_1" || got["order"] != 4411 {
		t.Fatalf("%v %v", got, err)
	}
	if _, has := orig[ApprovalArgument]; has {
		t.Fatal("the caller's map must not change")
	}
	if _, err := WithApproval(nil, ""); err == nil {
		t.Fatal("an empty approval id")
	}
}
