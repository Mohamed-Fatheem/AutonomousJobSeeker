"""Per-user job source choices. Existing accounts retain the pilot defaults."""
import json
from .models import SourcePreferences

ATS = ('greenhouse', 'lever', 'ashby')
ALERTS = ('linkedin', 'indeed', 'naukri', 'naukrigulf')
ALL = ATS + ALERTS
DEFAULT = frozenset(ATS + ALERTS[:-1])


def selected_platforms(db, user_id):
    row = db.get(SourcePreferences, user_id)
    if row is None:
        return set(DEFAULT)
    try:
        values = json.loads(row.platforms_json)
    except (TypeError, ValueError):
        return set()
    return set(values) & set(ALL) if isinstance(values, list) else set()


def save_platforms(db, user_id, values):
    selected = set(values)
    if selected - set(ALL):
        raise ValueError('Choose only the job platforms shown on this page')
    row = db.get(SourcePreferences, user_id)
    if row is None:
        row = SourcePreferences(user_id=user_id)
        db.add(row)
    row.platforms_json = json.dumps([name for name in ALL if name in selected])
    return selected
