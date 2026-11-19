# neuro-admin-client
Client library for Neuro Admin microservice

## Shared agent setup

Keep `apolo-agent-harness` as a sibling checkout in the services workspace.
Before starting work, run setup if the local role paths are missing or stale.
Run the command from the harness checkout.

```sh
# Regular sibling checkout
make setup SETUP_ARGS='--workspace .. --repo neuro-admin-client'

# Worktree
make setup SETUP_ARGS='--workspace ../.worktrees/<task> --repo neuro-admin-client'
```

Replace `<task>` with the worktree directory name. Setup writes the local role registrations for this checkout.
