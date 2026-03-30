# db-safety

Database safety guards for Claude Code sessions.

## What it checks

- **Database protection**: blocks docker compose down -v, docker volume rm/prune on production volumes, DROP DATABASE, FLUSHALL, dropdb, and other destructive database commands
- **Migration safety**: blocks prisma db push against production, warns on migration deploys, scans .sql files for destructive operations (DROP TABLE, TRUNCATE, etc.)

## Installation

```
claude plugin marketplace add wrxck/claude-plugins
claude plugin install db-safety@wrxck-claude-plugins
```
