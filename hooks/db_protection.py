#!/usr/bin/env python3
"""
Claude Code hook to protect production databases from accidental deletion.
Blocks commands that could destroy Docker volumes, database data, or
database containers in destructive ways.
"""

import json
import re
import sys


# Named volumes used by production databases
PROD_VOLUMES = [
    'postgres_data',
    'mysql_data',
    'redis_data',
    'mongodb_data',
    'moltbook-stats_pgdata',
    'natures-art_postgres_data',
    'natures-art_redis_data',
    'image-merger_redis-data',
    'thimble_postgres_data',
]

# Production database container names
PROD_CONTAINERS = [
    'shared-postgres',
    'shared-mysql',
    'shared-redis',
    'shared-mongodb',
    'moltbook-stats-db',
    'natures-art-db',
]

# Paths where Docker stores volume data
DOCKER_DATA_PATHS = [
    r'/var/lib/docker/volumes',
    r'/var/lib/docker',
    r'/var/lib/postgresql',
    r'/var/lib/mysql',
]


def check_command(command: str) -> str | None:
    """check if command could destroy production database data.
    returns a reason string if blocked, None if safe."""

    # docker compose down -v / --volumes (removes volumes)
    if re.search(r'\bdocker\s+compose\b.*\bdown\b.*(?:-v\b|--volumes\b)', command):
        return 'docker compose down -v removes all named volumes including database data'
    if re.search(r'\bdocker-compose\b.*\bdown\b.*(?:-v\b|--volumes\b)', command):
        return 'docker-compose down -v removes all named volumes including database data'

    # docker volume rm (any production volume)
    if re.search(r'\bdocker\s+volume\s+rm\b', command) or re.search(r'\bdocker\s+volume\s+remove\b', command):
        for vol in PROD_VOLUMES:
            if vol in command:
                return f'would delete production volume: {vol}'
        # also block blanket volume removal without specific names
        if re.search(r'\bdocker\s+volume\s+rm\s+\$', command):
            return 'bulk volume removal could delete production volumes'

    # docker volume prune
    if re.search(r'\bdocker\s+volume\s+prune\b', command):
        return 'docker volume prune can delete production volumes not currently in use'

    # docker system prune --volumes
    if re.search(r'\bdocker\s+system\s+prune\b', command):
        if re.search(r'--volumes\b', command):
            return 'docker system prune --volumes deletes all unused volumes including database data'
        if re.search(r'-a\b|--all\b', command):
            return 'docker system prune -a can affect database images; use without -a or --volumes'

    # docker rm -v (removes anonymous volumes attached to container)
    if re.search(r'\bdocker\s+rm\b.*-v', command):
        for container in PROD_CONTAINERS:
            if container in command:
                return f'docker rm -v would delete volumes attached to production database: {container}'

    # direct rm of docker volume paths or database data directories
    if re.search(r'\brm\b', command):
        for path in DOCKER_DATA_PATHS:
            if re.search(path, command):
                return f'rm targeting {path} would destroy database data on disk'

    # DROP DATABASE in raw SQL or psql/mysql commands
    if re.search(r'\bDROP\s+DATABASE\b', command, re.IGNORECASE):
        return 'DROP DATABASE would permanently destroy a production database'

    # dropping all tables
    if re.search(r'\bDROP\s+SCHEMA\s+.*CASCADE\b', command, re.IGNORECASE):
        return 'DROP SCHEMA CASCADE would destroy all tables in the schema'

    # truncating entire databases via CLI tools
    if re.search(r'\bdropdb\b', command):
        return 'dropdb would permanently destroy a production PostgreSQL database'
    if re.search(r'\bmysqladmin\b.*\bdrop\b', command):
        return 'mysqladmin drop would permanently destroy a production MySQL database'

    # mongo database drop
    if re.search(r'db\.dropDatabase\(\)', command):
        return 'db.dropDatabase() would permanently destroy a production MongoDB database'
    if re.search(r'\bmongosh?\b.*--eval.*dropDatabase', command):
        return 'mongosh dropDatabase would permanently destroy a production MongoDB database'

    # redis FLUSHALL / FLUSHDB
    if re.search(r'\bredis-cli\b.*\bFLUSHALL\b', command, re.IGNORECASE):
        return 'FLUSHALL would wipe all data from production Redis'
    if re.search(r'\bredis-cli\b.*\bFLUSHDB\b', command, re.IGNORECASE):
        return 'FLUSHDB would wipe data from a production Redis database'

    return None


def main():
    try:
        input_data = json.load(sys.stdin)
    except json.JSONDecodeError:
        sys.exit(0)

    tool_input = input_data.get('tool_input', {})
    command = tool_input.get('command', '')

    if not command:
        sys.exit(0)

    reason = check_command(command)
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
