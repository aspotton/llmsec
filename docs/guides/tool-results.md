# Tool results

Tool output can carry indirect prompt injection from email, web pages, APIs, files, and databases.

```python
result = await guard.ainspect_tool_result(tool_text)
```

V0.1 scans tool-result text. The roadmap adds first-class tool-call authorization, parameter roles, capabilities, effects, approvals, and source-influence policy.
