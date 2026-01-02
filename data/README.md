# Data Directory

This directory stores persistent data for Cipher Aegis:

## Subdirectories

### `events.db`
- SQLite database containing:
  - Captured network flows
  - Detected anomalies (red alerts)
  - System logs
  - Statistics

## Database Schema

### Tables:
1. **flows** - All captured network flows with features
2. **anomalies** - Red alerts (anomalous flows)
3. **system_logs** - Application logs
4. **statistics** - Aggregated metrics

## Storage Management

The database will grow over time. Use the cleanup feature:

```python
from db_manager import get_db

db = get_db()
db.clear_old_data(days=7)  # Delete data older than 7 days
```

## Backup

To backup the database:
```bash
cp data/events.db data/events_backup_$(date +%Y%m%d).db
```

## Reset

To start fresh:
```bash
rm data/events.db
# Will be recreated automatically on next run
```
