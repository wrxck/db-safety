#!/usr/bin/env python3
"""
Claude Code PreToolUse hook for Bash.
Protects against dangerous database migration commands:
- Blocks prisma db push against production
- Warns on prisma migrate deploy / drizzle-kit push
- Reads .sql files referenced in commands and flags destructive operations
"""

import json
import os
import re
import sys


# commands that trigger migration checks
MIGRATION_COMMANDS = [
    r'\bprisma\s+migrate\s+deploy\b',
    r'\bprisma\s+db\s+push\b',
    r'\bdrizzle-kit\s+push\b',
    r'\bdrizzle-kit\s+migrate\b',
]

# destructive SQL patterns
DESTRUCTIVE_SQL = [
    (r'\bDROP\s+TABLE\b', 'DROP TABLE'),
    (r'\bDROP\s+COLUMN\b', 'DROP COLUMN'),
    (r'\bALTER\s+TABLE\s+\S+\s+DROP\b', 'ALTER TABLE ... DROP'),
    (r'\bTRUNCATE\b', 'TRUNCATE'),
    (r'\bDROP\s+INDEX\b', 'DROP INDEX'),
    (r'\bDROP\s+SCHEMA\b', 'DROP SCHEMA'),
]

# safe SQL patterns (no warning needed)
SAFE_SQL = [
    r'\bCREATE\s+TABLE\b',
    r'\bADD\s+COLUMN\b',
    r'\bCREATE\s+INDEX\b',
    r'\bCREATE\s+UNIQUE\s+INDEX\b',
    r'\bALTER\s+TABLE\s+\S+\s+ADD\b',
]

# production indicators in connection strings or environment
PROD_INDICATORS = [
    r'production',
    r'prod\b',
    r'\.com\b',
    r'\.io\b',
    r'rds\.amazonaws',
    r'neon\.tech',
    r'supabase\.co',
    r'planetscale',
]


def read_sql_file(command: str) -> str | None:
    """try to find and read a .sql file referenced in the command"""
    # look for .sql file references
    sql_files = re.findall(r'[\w./-]+\.sql\b', command)
    for sql_file in sql_files:
        # resolve relative paths
        if not os.path.isabs(sql_file):
            sql_file = os.path.join(os.getcwd(), sql_file)
        try:
            with open(sql_file, 'r') as f:
                return f.read()
        except (FileNotFoundError, PermissionError):
            continue
    return None


def check_command(command: str) -> tuple[str | None, bool]:
    """check migration command safety.
    returns (message, is_blocking) — message is None if safe."""

    # check for prisma db push (potentially destructive)
    if re.search(r'\bprisma\s+db\s+push\b', command):
        # check if targeting production
        for indicator in PROD_INDICATORS:
            if re.search(indicator, command, re.IGNORECASE):
                return (
                    'BLOCKED: "prisma db push" against what appears to be a production database.\n'
                    'prisma db push can drop columns and tables to match schema.\n'
                    'use "prisma migrate deploy" with reviewed migration files instead.',
                    True,
                )
        # even non-prod, warn
        return (
            'WARNING: "prisma db push" can drop columns and data to match schema.\n'
            'ensure this is a development database. for production, use "prisma migrate deploy".',
            False,
        )

    # check for other migration commands (warn, don't block)
    for pattern in MIGRATION_COMMANDS:
        if re.search(pattern, command):
            return (
                f'migration command detected: ensure you have a database backup before proceeding.\n'
                f'command: {command.strip()[:100]}',
                False,
            )

    # check for psql/mysql with .sql file
    if re.search(r'\b(psql|mysql)\b', command):
        sql_content = read_sql_file(command)
        if sql_content:
            destructive = []
            for pattern, name in DESTRUCTIVE_SQL:
                if re.search(pattern, sql_content, re.IGNORECASE):
                    destructive.append(name)

            if destructive:
                return (
                    f'BLOCKED: destructive migration detected in SQL file.\n'
                    f'operations found: {", ".join(destructive)}\n'
                    f'these operations are irreversible. review the SQL file carefully and run manually if intended.',
                    True,
                )

    return (None, False)


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')

    if not command:
        sys.exit(0)

    # quick check — does the command involve any migration-related tools?
    if not any(kw in command.lower() for kw in ['prisma', 'drizzle', 'psql', 'mysql', '.sql']):
        sys.exit(0)

    message, is_blocking = check_command(command)

    if message:
        if is_blocking:
            print(message, file=sys.stderr)
            sys.exit(2)
        else:
            # non-blocking warning via additionalContext
            output = {
                'hookSpecificOutput': {
                    'hookEventName': 'PreToolUse',
                    'additionalContext': message,
                }
            }
            print(json.dumps(output))
            sys.exit(0)

    sys.exit(0)


if __name__ == '__main__':
    main()
