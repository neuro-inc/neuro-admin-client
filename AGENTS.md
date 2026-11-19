<!-- apolo-agent-harness:start -->
## Shared Apolo agent harness

Locate the shared `apolo-agent-harness` checkout before starting work.
From the workspace root, check `./apolo-agent-harness`.
From this file's directory, check `../apolo-agent-harness` for a sibling checkout.
For a checkout under `.worktrees/<task>/<repository>`, check `../../../apolo-agent-harness`.
For other layouts, locate the harness from a valid `config_file` path in `.codex/config.toml`.
If that path is unavailable, use the workspace's designated harness checkout.

Run `make setup-check` from the harness checkout to check the local setup.
If setup is missing or stale, run `make setup` with the same arguments.
Pass the directory containing this service checkout as `--workspace` and select this service with `--repo` in `SETUP_ARGS`.
For the workspace root, pass that directory as `--workspace` and omit `--repo`.
Then read `instructions/AGENTS.md` in the harness and follow its relevant guidance.
If the harness is unavailable, report that limitation and follow the available repository instructions.
Keep service-specific rules outside this managed block.
<!-- apolo-agent-harness:end -->
