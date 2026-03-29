# Run Task — Project Worldline

## Instructions

You are executing a development task for Project Worldline. Read `CLAUDE.md` at the repo root for full context, architecture overview, and coding standards.

## Execution Protocol

1. **Read CLAUDE.md first** — understand the architecture and standards.
2. **Create branch** — `git checkout -b <scope>-<short-description>` (e.g., `contracts-plonk-adapter`)
3. **Review scope** — confirm the task's expected artifacts and test targets.
4. **Implement** — follow coding standards in CLAUDE.md. Use sub-agents (`task` tool) where file scopes are independent.
5. **Test** — run scoped tests. All must pass with zero failures.
6. **Verify** — confirm all deliverables match the task requirements.
7. **Commit** — `<scope>: <description>`. Push branch.
8. **Report** — output a structured completion report:

```
Task: $ARGUMENTS — Complete. Report:
- Files created/modified: [list]
- Tests: [count] passing, [count] failing
- Artifacts: [list with sizes]
- Ready for: review
```

## Sub-Agent Policy

If splitting work across sub-agents:

- Define file ownership per agent BEFORE spawning
- Pass interface signatures (types, ABIs, trait definitions) to dependent agents
- Each agent runs only its scoped tests
- Orchestrator assembles and runs the full test suite at the end
