<!-- apolo-agent-harness:start -->
## Shared Apolo agent harness

Locate the shared `apolo-agent-harness` checkout before starting work.
From the workspace root, check `./apolo-agent-harness`.
From this file's directory, check `../apolo-agent-harness` for a sibling checkout.
For a checkout under `.worktrees/<task>/<repository>`, check `../../../apolo-agent-harness`.
For other layouts, locate the harness from a valid `config_file` path in `.codex/config.toml`.
If that path is unavailable, use the workspace's designated harness checkout.

To check only the current service, run this command from the harness checkout.
Replace `<service-parent>` with the directory containing the service checkout.
Replace `<service-name>` with the name of the checkout directory.

```sh
make setup-check SETUP_ARGS='--workspace "<service-parent>" --repo "<service-name>"'
```

If the check reports missing or stale setup, run `make setup` with the same arguments.
For workspace-wide setup, see the harness README.
Then read `instructions/AGENTS.md` in the harness and follow its relevant guidance.
If the harness is unavailable, report that limitation and follow the available repository instructions.
Keep service-specific rules outside this managed block.
<!-- apolo-agent-harness:end -->
