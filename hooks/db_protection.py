#!/usr/bin/env python3
"""
Claude Code PreToolUse hook to protect production databases from accidental deletion.
Blocks commands that could destroy Docker volumes, database data, or
database containers in destructive ways.
"""

import json
import os
import re
import sys
from pathlib import Path


DEFAULT_VOLUME_PATTERN = r'.*_(data|pgdata|mysql|mongo|postgres|redis)$'


PROD_CONTAINERS = [
    'shared-postgres',
    'shared-mysql',
    'shared-redis',
    'shared-mongodb',
]


DOCKER_DATA_PATHS = [
    r'/var/lib/docker/volumes',
    r'/var/lib/docker',
    r'/var/lib/postgresql',
    r'/var/lib/mysql',
]


VOLUME_FLAG_RE = r'(?:-v\b|-vf\b|-fv\b|-V\b|--volumes\b)'


def load_user_config() -> dict:
    try:
        home = Path.home()
        path = home / '.claude' / 'db-safety.json'
        if path.is_file():
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def compile_volume_matcher(config: dict):
    explicit = config.get('prod_volumes') or []
    patterns = config.get('prod_volume_patterns') or []

    compiled_patterns = []
    for p in patterns:
        try:
            compiled_patterns.append(re.compile(p))
        except re.error:
            continue

    if not explicit and not compiled_patterns:
        compiled_patterns.append(re.compile(DEFAULT_VOLUME_PATTERN))

    def matches(name: str) -> bool:
        if name in explicit:
            return True
        for pattern in compiled_patterns:
            if pattern.search(name):
                return True
        return False

    return matches


def split_commands(command: str) -> list[str]:
    parts = re.split(r'(?:\|\||&&|;|\|)', command)
    return [p.strip() for p in parts if p.strip()]


def acknowledged_volume(env_name: str | None) -> str | None:
    if env_name is None:
        return None
    val = os.environ.get('CLAUDE_ACKNOWLEDGE_VOLUME_DESTRUCTION', '')
    return val.strip() if val.strip() else None


def check_segment(segment: str, volume_matches) -> str | None:
    if re.search(r'\bdocker\s+compose\b.*\bdown\b.*' + VOLUME_FLAG_RE, segment) or \
       re.search(VOLUME_FLAG_RE + r'.*\bdocker\s+compose\b.*\bdown\b', segment):
        return 'docker compose down with volume removal flag - removes named volumes including database data'
    if re.search(r'\bdocker-compose\b.*\bdown\b.*' + VOLUME_FLAG_RE, segment) or \
       re.search(VOLUME_FLAG_RE + r'.*\bdocker-compose\b.*\bdown\b', segment):
        return 'docker-compose down with volume removal flag - removes named volumes including database data'

    if re.search(r'\bdocker\s+compose\b.*\bdown\b', segment):
        if re.search(r'\s-[a-zA-Z]*v[a-zA-Z]*\b', segment) or re.search(r'--volumes\b', segment):
            return 'docker compose down -v variant detected - removes named volumes'

    if re.search(r'\bdocker\s+volume\s+(?:rm|remove)\b', segment):
        if re.search(r'\bdocker\s+volume\s+(?:rm|remove)\s+.*\$\(', segment) or \
           re.search(r'\bdocker\s+volume\s+(?:rm|remove)\s+.*`', segment):
            return 'docker volume rm with subshell expansion - dynamic content cannot be verified safely'
        acknowledged = acknowledged_volume('CLAUDE_ACKNOWLEDGE_VOLUME_DESTRUCTION')
        m = re.search(r'\bdocker\s+volume\s+(?:rm|remove)\b(.*)$', segment)
        tail = m.group(1) if m else ''
        tokens = [t for t in re.split(r'\s+', tail.strip()) if t and not t.startswith('-')]
        if not tokens:
            return 'docker volume rm without explicit arguments - would be interactive or match nothing safely'
        flagged = [t for t in tokens if volume_matches(t)]
        if flagged:
            if acknowledged and acknowledged in flagged and len(flagged) == 1:
                return None
            return f'would delete volumes matching production pattern: {", ".join(flagged)}'
        if acknowledged is None:
            return (
                'docker volume rm blocked by default - set '
                'CLAUDE_ACKNOWLEDGE_VOLUME_DESTRUCTION=<volume> to allow'
            )

    if re.search(r'\bdocker\s+volume\s+prune\b', segment):
        return 'docker volume prune can delete volumes not currently attached to a running container'

    if re.search(r'\bdocker\s+system\s+prune\b', segment):
        if re.search(r'--volumes\b', segment):
            return 'docker system prune --volumes deletes unused volumes including database data'
        if re.search(r'\s-a\b|--all\b', segment):
            return 'docker system prune -a can affect database images'

    if re.search(r'\bdocker\s+rm\b', segment):
        if re.search(r'\s-[a-zA-Z]*v[a-zA-Z]*\b', segment) or re.search(r'--volumes\b', segment):
            for container in PROD_CONTAINERS:
                if container in segment:
                    return f'docker rm -v against production database container: {container}'
            if re.search(r'\bdocker\s+rm\b.*\$\(', segment):
                return 'docker rm -v with subshell expansion - cannot verify targets'

    if re.search(r'\brm\b', segment):
        for path in DOCKER_DATA_PATHS:
            if re.search(path, segment):
                return f'rm targeting {path} would destroy database data on disk'

    if re.search(r'\bDROP\s+DATABASE\b', segment, re.IGNORECASE):
        return 'DROP DATABASE would permanently destroy a database'
    if re.search(r'\bDROP\s+SCHEMA\s+.*CASCADE\b', segment, re.IGNORECASE):
        return 'DROP SCHEMA CASCADE would destroy all tables in the schema'
    if re.search(r'\bdropdb\b', segment):
        return 'dropdb would permanently destroy a PostgreSQL database'
    if re.search(r'\bmysqladmin\b.*\bdrop\b', segment):
        return 'mysqladmin drop would permanently destroy a MySQL database'
    if re.search(r'db\.dropDatabase\(\)', segment):
        return 'db.dropDatabase() would permanently destroy a MongoDB database'
    if re.search(r'\bmongosh?\b.*--eval.*dropDatabase', segment):
        return 'mongosh dropDatabase would permanently destroy a MongoDB database'
    if re.search(r'\bredis-cli\b.*\bFLUSHALL\b', segment, re.IGNORECASE):
        return 'FLUSHALL would wipe all data from Redis'
    if re.search(r'\bredis-cli\b.*\bFLUSHDB\b', segment, re.IGNORECASE):
        return 'FLUSHDB would wipe data from a Redis database'

    return None


def check_command(command: str, volume_matches) -> str | None:
    for segment in split_commands(command):
        reason = check_segment(segment, volume_matches)
        if reason:
            return reason
    return None


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("BLOCKED: db-safety failed to parse hook input", file=sys.stderr)
        sys.exit(2)

    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')
    if not command:
        sys.exit(0)

    config = load_user_config()
    volume_matches = compile_volume_matcher(config)

    reason = check_command(command, volume_matches)
    if reason:
        print("BLOCKED: production database protection", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  reason: {reason}", file=sys.stderr)
        print("", file=sys.stderr)
        print(f"  command: {command}", file=sys.stderr)
        print("", file=sys.stderr)
        print("this command could permanently destroy production data.", file=sys.stderr)
        print("if you genuinely need to run this, do it manually in the terminal.", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == '__main__':
    main()
