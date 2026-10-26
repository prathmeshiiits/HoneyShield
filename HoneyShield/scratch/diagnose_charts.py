import urllib.request
import json
import sqlite3

base_url = 'http://127.0.0.1:5000'

# 1. Database records
conn = sqlite3.connect('data/honeyshield.sqlite3')
conn.row_factory = sqlite3.Row
print('--- SESSIONS IN DB ---')
sessions = conn.execute('SELECT session_key, risk_score, risk_band, decoy_active, is_simulated, is_isolated, scenario FROM sessions').fetchall()
print(f'Total sessions: {len(sessions)}')
for s in sessions:
    print(dict(s))

print('\n--- EVENTS IN DB ---')
events = conn.execute('SELECT id, session_key, event_type, is_isolated, event_at FROM events ORDER BY id DESC LIMIT 15').fetchall()
total_events = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
print(f'Total events: {total_events}')
for e in events:
    print(dict(e))

# 2. API Responses
print('\n--- API /api/metrics ---')
try:
    with urllib.request.urlopen(f'{base_url}/api/metrics') as r:
        metrics = json.loads(r.read().decode())
        print('Summary:', json.dumps(metrics.get('summary', {}), indent=2))
        print('Risk Dist:', json.dumps(metrics.get('risk_distribution', {}), indent=2))
except Exception as exc:
    print('Error /api/metrics:', exc)

print('\n--- API /api/chart/attempts?window=300 ---')
try:
    with urllib.request.urlopen(f'{base_url}/api/chart/attempts?window=300') as r:
        c300 = json.loads(r.read().decode())
        print('Window 300s:', c300)
except Exception as exc:
    print('Error /api/chart/attempts?window=300:', exc)

print('\n--- API /api/chart/attempts?window=3600 ---')
try:
    with urllib.request.urlopen(f'{base_url}/api/chart/attempts?window=3600') as r:
        c3600 = json.loads(r.read().decode())
        print('Window 3600s:', c3600)
except Exception as exc:
    print('Error /api/chart/attempts?window=3600:', exc)

print('\n--- API /api/chart/attempts?window=86400 ---')
try:
    with urllib.request.urlopen(f'{base_url}/api/chart/attempts?window=86400') as r:
        c86400 = json.loads(r.read().decode())
        print('Window 86400s:', c86400)
except Exception as exc:
    print('Error /api/chart/attempts?window=86400:', exc)
