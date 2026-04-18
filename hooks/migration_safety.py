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


MIGRATION_COMMANDS = [
    r'\bprisma\s+migrate\s+deploy\b',
    r'\bprisma\s+db\s+push\b',
    r'\bdrizzle-kit\s+push\b',
    r'\bdrizzle-kit\s+migrate\b',
]


DESTRUCTIVE_SQL = [
    (r'\bDROP\s+TABLE\b', 'DROP TABLE'),
    (r'\bDROP\s+COLUMN\b', 'DROP COLUMN'),
    (r'\bALTER\s+TABLE\s+\S+\s+DROP\b', 'ALTER TABLE ... DROP'),
    (r'\bTRUNCATE\b', 'TRUNCATE'),
    (r'\bDROP\s+INDEX\b', 'DROP INDEX'),
    (r'\bDROP\s+SCHEMA\b', 'DROP SCHEMA'),
]


PROD_INDICATORS = [
    r'\bproduction\b',
    r'\bprod-',
    r'\.prod\.',
    r'\bprod_',
    r'\bPROD\b',
    r'PRODUCTION',
    r'rds\.amazonaws',
    r'neon\.tech',
    r'supabase\.co',
    r'planetscale',
]


def project_cwd(input_data: dict, tool_input: dict) -> str:
    fp = tool_input.get('file_path')
    if fp:
        try:
            parent = os.path.dirname(os.path.abspath(fp))
            if parent and os.path.isdir(parent):
                return parent
        except OSError:
            pass
    for key in ('cwd', 'workingDirectory', 'project_dir'):
        val = input_data.get(key)
        if val and isinstance(val, str) and os.path.isdir(val):
            return val
    return os.getcwd()


def read_sql_file(command: str, base_dir: str) -> str | None:
    sql_files = re.findall(r'[\w./-]+\.sql\b', command)
    for sql_file in sql_files:
        path = sql_file
        if not os.path.isabs(path):
            path = os.path.join(base_dir, path)
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return None


def env_database_url_is_prod() -> bool:
    val = os.environ.get('DATABASE_URL', '')
    if not val:
        return False
    return bool(re.search(r'(prod|production)', val, re.IGNORECASE))


def looks_prod(command: str) -> bool:
    for indicator in PROD_INDICATORS:
        if re.search(indicator, command, re.IGNORECASE):
            return True
    return env_database_url_is_prod()


def check_command(command: str, base_dir: str) -> tuple[str | None, bool]:
    if re.search(r'\bprisma\s+db\s+push\b', command):
        if looks_prod(command):
            return (
                'BLOCKED: "prisma db push" targeting a production database.\n'
                'prisma db push can drop columns and tables to match schema.\n'
                'use "prisma migrate deploy" with reviewed migration files instead.',
                True,
            )
        return (
            'WARNING: "prisma db push" can drop columns and data to match schema.\n'
            'ensure this is a development database. for production, use "prisma migrate deploy".',
            False,
        )

    for pattern in MIGRATION_COMMANDS:
        if re.search(pattern, command):
            return (
                f'migration command detected: ensure you have a database backup before proceeding.\n'
                f'command: {command.strip()[:100]}',
                False,
            )

    if re.search(r'\b(psql|mysql)\b', command):
        sql_content = read_sql_file(command, base_dir)
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
        print("BLOCKED: migration-safety failed to parse hook input", file=sys.stderr)
        sys.exit(2)

    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')
    if not command:
        sys.exit(0)

    if not any(kw in command.lower() for kw in ['prisma', 'drizzle', 'psql', 'mysql', '.sql']):
        sys.exit(0)

    base_dir = project_cwd(input_data, tool_input)

    message, is_blocking = check_command(command, base_dir)
    if message:
        if is_blocking:
            print(message, file=sys.stderr)
            sys.exit(2)
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
