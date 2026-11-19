# neuro-admin-client
Client library for Neuro Admin microservice

## Shared agent setup

Keep `apolo-agent-harness` as a sibling checkout in the services workspace.
Before starting work, check setup for this service only.
Run the command from the harness checkout.

```sh
# Regular sibling checkout
make setup-check SETUP_ARGS='--workspace .. --repo neuro-admin-client'

# Worktree
make setup-check SETUP_ARGS='--workspace ../.worktrees/<task> --repo neuro-admin-client'
```

Replace `<task>` with the worktree directory name. If the check reports missing or stale setup, run `make setup` with the same arguments.
