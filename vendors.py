"""Optional IEEE OUI registry cache. Device MACs never leave this machine."""
import csv
from datetime import datetime, timezone
from functools import lru_cache
import io
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request

SOURCE = 'https://standards-oui.ieee.org/oui/oui.csv'


def parse_ieee(data):
    rows = csv.DictReader(io.StringIO(data.decode('utf-8-sig')))
    if not rows.fieldnames or not {'Assignment', 'Organization Name'}.issubset(rows.fieldnames):
        raise ValueError('Geçerli IEEE CSV dosyası alınamadı.')
    registry = {}
    for row in rows:
        prefix = row.get('Assignment', '').strip().upper()
        name = row.get('Organization Name', '').strip()
        if re.fullmatch(r'[0-9A-F]{6}', prefix) and 0 < len(name) <= 300:
            registry[prefix] = name
    if not registry:
        raise ValueError('Üretici listesi boş; mevcut liste korunuyor.')
    return registry


def update(path):
    with urllib.request.urlopen(SOURCE, timeout=25) as response:
        data = response.read(12 * 1024 * 1024 + 1)
    if len(data) > 12 * 1024 * 1024:
        raise ValueError('IEEE dosyası boyut sınırını aştı.')
    registry = parse_ieee(data)
    payload = {'source': SOURCE, 'updated_at': datetime.now(timezone.utc).isoformat(), 'prefixes': registry}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='oui-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            json.dump(payload, file, ensure_ascii=False)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(registry)


@lru_cache(maxsize=2)
def _cached(path, modified):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if isinstance(data, dict) and isinstance(data.get('prefixes'), dict):
            return data
        return {'prefixes': {}}
    except (ValueError, OSError):
        return {'prefixes': {}}


def load(path):
    path = Path(path)
    return _cached(str(path), path.stat().st_mtime_ns) if path.exists() else {'prefixes': {}}


def lookup(macs, registry):
    owners = set()
    for mac in macs:
        compact = mac.replace(':', '').upper()
        if re.fullmatch(r'[0-9A-F]{12}', compact) and not int(compact[:2], 16) & 3:
            owner = registry.get(compact[:6])
            if owner:
                owners.add(owner)
    return ', '.join(sorted(owners))
