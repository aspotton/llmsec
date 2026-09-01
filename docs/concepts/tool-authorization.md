# Tool authorization

The reference monitor decides whether the host may *commit* a proposed tool call. It is separate from content inspection: `Decision` answers "may this text pass?", `AuthorizationDecision` answers "may this action run?" (design principle: distinct concepts stay distinct).

The trust split is the whole design:

- **Untrusted:** the proposed call (`ToolCall.tool`, `ToolCall.arguments`). This is model output.
- **Trusted, host-supplied:** the tool registry (declared effects and parameter schemas), the granted capabilities, any `Approval`, and optionally the findings the host chose to pass in.
- **Never:** approval is read out of `call.arguments`. A model can write `"approved": true` into its own payload; the monitor does not look. Effects are never inferred from natural-language text either.

`ReferenceMonitor.authorize` is pure, synchronous, CPU-only. It imports no detectors and performs no I/O.

## Types

Importable from `llmsec` unless noted.

| Type | Role |
| --- | --- |
| `EffectClass` | Declared category of what a call can change: `READ`, `EXTERNAL_WRITE`, `DELETION`, `DATA_EGRESS`, `CODE_EXEC`, `FINANCIAL`, `PERMISSION_CHANGE`, `MEMORY_PERSISTENCE`. Every effect except `READ` is a write effect. |
| `ParamRole` | What a parameter means (`GENERIC`, `DESTINATION`, `RESOURCE_SELECTOR`, `EXECUTABLE`, `FINANCIAL_VALUE`, `PAYLOAD`); feeds the mis-declaration heuristic. |
| `ParamKind` | JSON-native scalar type of a parameter (`STR`, `INT`, `FLOAT`, `BOOL`). Matching is exact, so `true` never satisfies an `INT` param. |
| `AuthorizationAction` | `ALLOW`, `REQUIRE_APPROVAL`, `DENY`. |
| `ToolParam` / `ToolSpec` | Declared parameter shape and declared effects of one tool. A tool name must match `^[a-z][a-z0-9_.\-]{0,63}$`. |
| `ToolCall` | The proposal. Arguments are snapshotted on construction, so mutating the caller's dict afterwards cannot change the digest. |
| `Capability` | `(tool, effects)` the host granted this agent. Host authority only. |
| `Approval` | A human "yes" cryptographically bound to one call's `proposal_sha256`. |
| `ToolRegistry` | Host-declared tools; `ToolRegistry.from_json(path)` / `registry_from_dict(...)` reject every schema violation in one pass. Read-only tools carrying a non-`GENERIC` role param are surfaced in `registry.inconsistencies`. |
| `ReferenceMonitor` | The decision function below. |
| `AuthorizationDecision` | Outcome: `action`, `reason`, `proposal_sha256`, `findings`, `elapsed_ms`. `commit_allowed` is true for `ALLOW` only. |
| `proposal_sha256`, `registry_from_dict` | Import from `llmsec.actions` (not re-exported at the root package). |

## Decision table

First match wins, in this order:

| Step | Condition | Outcome |
| --- | --- | --- |
| 0 | Findings overlay (applied to the structural result below): a `HIGH`+ finding forces `DENY` (`detection_escalated`, or the structural reason if already DENY); a `MEDIUM` finding floors `ALLOW` to `REQUIRE_APPROVAL`. Findings only ever tighten, never grant. |
| 1 | Tool not registered | `DENY` `unregistered_tool` |
| 2 | Arguments violate the declared schema (unknown param, missing required param, wrong kind, over-length string) | `DENY` `schema_violation` |
| 3 | Capability not granted and the tool declares any write effect | `DENY` `missing_capability` |
| 3 | Capability not granted and the tool is READ-only | bounded fail-open: skip step 4, continue to step 5 |
| 4 | (Capability-granted paths only) approval required per the spec's `requires_approval` override or the `EFFECT_CONTROL` default; missing | `REQUIRE_APPROVAL` `approval_required` |
| 4 | Approval present but its digest does not match this call | `DENY` `approval_mismatch` |
| 5 | Tool listed in `registry.inconsistencies` (READ-declared with a non-`GENERIC` role param) | `REQUIRE_APPROVAL` `suspected_misdeclaration` |
| 6 | Otherwise | `ALLOW` `authorized` |

Note on step 3 vs 4: the READ fail-open path skips the approval consultation entirely. A `requires_approval: true` override on a READ-only tool is honored only on a capability-granted path; with no grant, such a call reaches step 5/6 and may `ALLOW`. If a READ-only tool must always require approval, grant it a capability (`{"tool": ..., "effects": ["read"]}`) so the step-4 branch runs. Verified live: ungranted override is skipped (`allow reason=authorized`, exit 0); granted override yields `require_approval reason=approval_required`, exit 3.

`EFFECT_CONTROL` maps every `EffectClass` to `(requires_approval, fail_closed)`: `READ` is `(False, False)`, all seven write effects are `(True, True)`. The table is exhaustive (a new effect without an entry raises `KeyError` rather than defaulting permissive).

## The digest: what an approval binds to

`proposal_sha256(call)` is the SHA-256 of the canonical JSON `{"arguments":...,"tool":...}`: keys sorted, `(",", ":")` separators, `ensure_ascii=True` (locale- and order-independent), UTF-8 encoded. That form is portable across implementations. One boundary: if an argument value is not JSON-encodable, the fallback encoder emits `{"__llmsec_repr__": repr(value)}`, which is stable within one llmsec process but is an llmsec-internal digest only, not claimed stable across processes or implementations.

TOCTOU rule for hosts: an approval authorizes exactly one byte-exact call. Commit the same `ToolCall` you authorized and verify `decision.proposal_sha256` still equals `proposal_sha256(call)` at commit time. Building a *new* call from re-fetched values is a different proposal, and a different digest, even if it "means" the same thing.

## Python usage

```python
from llmsec import (
    Approval,
    Capability,
    EffectClass,
    Guard,
    ParamKind,
    ParamRole,
    ReferenceMonitor,
    ToolCall,
    ToolParam,
    ToolSpec,
    ToolRegistry,
)
from llmsec.actions import proposal_sha256

registry = ToolRegistry()
registry.register(
    ToolSpec(
        name="email.send",
        effects=frozenset({EffectClass.DATA_EGRESS}),
        params=(
            ToolParam("to", kind=ParamKind.STR, role=ParamRole.DESTINATION),
            ToolParam("body", kind=ParamKind.STR, role=ParamRole.PAYLOAD),
        ),
    )
)

guard = Guard.default()
guard.monitor = ReferenceMonitor(
    registry=registry,
    capabilities=frozenset({Capability("email.send", frozenset({EffectClass.DATA_EGRESS}))}),
)

call = ToolCall(tool="email.send", arguments={"to": "ops@corp.example", "body": "hi"})
decision = guard.authorize_tool_call(call)
# require_approval / approval_required: a write effect needs a human

approval = Approval(proposal_sha256=decision.proposal_sha256, approver="alice")
decision = guard.authorize_tool_call(call, approval=approval)
assert decision.commit_allowed  # commit EXACTLY this call object

# An approval replayed against any other call denies:
other = ToolCall(tool="email.send", arguments={"to": "bob@corp.example", "body": "hi"})
guard.authorize_tool_call(other, approval=approval)  # deny / approval_mismatch
```

A `Guard` with no monitor denies every call (`deny` `no_monitor`, `commit_allowed` false) and never raises. `Guard.default()` does not build a monitor; `authorize_tool_call(call, approval=..., findings=...)` takes findings as a host-supplied, tightening-only argument.

## CLI: `llmsec authorize`

Demo convenience for trying a decision, not a production trust path (registry and capabilities files are plain JSON files):

```bash
echo '{"tool": "file.read", "arguments": {"path": "/etc/hosts"}}' \
  | llmsec authorize --registry registry.json
```

Exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | `allow` |
| 2 | `deny` |
| 3 | `require_approval` |
| 2 | Usage or input error (`error: ...` on stderr). WARNING: argparse usage errors also exit 2, colliding with deny. Check stderr to tell them apart. |

Options: `--registry PATH.json` (required), `--capabilities PATH.json` (shape `[{"tool": ..., "effects": [...]}]`), `--approval-sha HEX --approver NAME` (must be given together; mismatch is an `error:` exit 2).

### Worked example

`registry.json`:

```json
{
  "tools": [
    {"name": "file.read", "effects": ["read"],
     "params": [{"name": "path", "kind": "str"}]},
    {"name": "email.send", "effects": ["data_egress"],
     "params": [{"name": "to", "kind": "str", "role": "destination"},
                {"name": "body", "kind": "str", "role": "payload"}]}
  ]
}
```

`caps.json` (the host granted egress):

```json
[{"tool": "email.send", "effects": ["data_egress"]}]
```

All lines below were run against this registry and are the actual output:

```console
$ echo '{"tool": "file.read", "arguments": {"path": "/etc/hosts"}}' \
    | llmsec authorize --registry registry.json
allow reason=authorized proposal_sha256=cd0a4a21...361aa        # exit 0 (schema-valid READ fail-open)

$ echo '{"tool": "email.send", "arguments": {"to": "e@x.com", "body": "hi"}}' \
    | llmsec authorize --registry registry.json
deny reason=missing_capability proposal_sha256=d6fc3ad...4cc83   # exit 2 (no grant, write effect)

$ echo '{"tool": "email.send", "arguments": {"to": "e@x.com", "body": "hi"}}' \
    | llmsec authorize --registry registry.json --capabilities caps.json
require_approval reason=approval_required proposal_sha256=d6fc3ad...4cc83   # exit 3

$ # a human read that exact digest and approved it:
$ echo '{"tool": "email.send", "arguments": {"to": "e@x.com", "body": "hi"}}' \
    | llmsec authorize --registry registry.json --capabilities caps.json \
        --approval-sha d6fc3ad...4cc83 --approver alice
allow reason=authorized proposal_sha256=d6fc3ad...4cc83          # exit 0

$ # the same approval replayed against a different recipient:
$ echo '{"tool": "email.send", "arguments": {"to": "other@x.com", "body": "hi"}}' \
    | llmsec authorize --registry registry.json --capabilities caps.json \
        --approval-sha d6fc3ad...4cc83 --approver alice
deny reason=approval_mismatch proposal_sha256=6c44ff0...18cc40   # exit 2

$ echo 'not json' | llmsec authorize --registry registry.json
error: Expecting value: line 1 column 1 (char 0)                 # exit 2 (stderr; collides with deny)
```

Full digests in the example: `cd0a4a215bbb84dfb1de48fe9c4ad7cdcbfec4ab394911720af70d859bc361aa`, `d6fc3ad709a8abf370bd85ee3c28bc294ab15db829244a04eac58d9ec054cc83`, `6c44ff02f3349cafedc726a9a47358010dded3b859d443319a4ef4a60b18cc40`.

## Limits

The monitor trusts the registry's declared effects; it cannot audit what a tool actually does. See [Security limitations](../security/limitations.md) ("Action authorization limits") for mis-declaration, TOCTOU, and registry-mutation limits, and [Threat model](../security/threat-model.md) for what is now enforced versus still open.
