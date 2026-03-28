# Run Chunk — Project Worldline

## Instructions

You are executing **Chunk $ARGUMENTS** of the Project Worldline nine-chunk remediation workflow. Read `CLAUDE.md` at the repo root for full context, dependency graph, and coding standards.

## Execution Protocol

1. **Read CLAUDE.md first** — confirm chunk status and dependencies are met.
2. **Create branch** — `git checkout -b chunk-$ARGUMENTS-<short-description>`
3. **Review chunk spec** — confirm scope, expected artifacts, and test targets.
4. **Implement** — follow coding standards in CLAUDE.md. Use sub-agents (`task` tool) where file scopes are independent.
5. **Test** — run scoped tests. All must pass with zero failures.
6. **Verify** — confirm all deliverables match the chunk spec checklist.
7. **Commit** — `chunk-$ARGUMENTS: <description>`. Push branch.
8. **Report** — output a structured completion report:

```
Chunk $ARGUMENTS — Complete. Report:
- Files created/modified: [list]
- Tests: [count] passing, [count] failing
- Artifacts: [list with sizes]
- Dependencies satisfied: [list which prior chunks were used]
- Ready for: Chunk [next] confirmation
```

## Sub-Agent Policy

If splitting work within this chunk:

- Define file ownership per agent BEFORE spawning
- Pass interface signatures (types, ABIs, trait definitions) to dependent agents
- Each agent runs only its scoped tests
- Orchestrator assembles and runs the full chunk test suite at the end

## Chunk Specs

Refer to the audit remediation workflow document for detailed per-chunk requirements. If the spec is not available in context, ask the user to provide it before proceeding.
