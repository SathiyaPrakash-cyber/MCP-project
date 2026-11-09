"""
Back-fill historical audit records into Elasticsearch.

Reads every logs/mcp_audit_*.ndjson file written by gateway/audit_logger.py and
posts the records to the Elasticsearch bulk API, so that the Kibana dashboard
(Figure 4.7 in the dissertation) can be reproduced from logs captured before
live shipping was enabled. Live shipping happens in audit_logger._ship_to_es;
this script is only for historical data.

Usage:  python scripts/ingest_to_es.py
"""

import httpx, json
from pathlib import Path

ES_URL = "http://localhost:9200"
INDEX  = "mcp-gateway-audit"

def run():
    files = sorted(Path("logs").glob("mcp_audit_*.ndjson"))
    if not files:
        print("No audit files found"); return
    total = 0
    for f in files:
        lines = [l for l in f.read_text().splitlines() if l.strip()]
        if not lines: continue
        bulk = []
        for line in lines:
            bulk.append(json.dumps({"index": {"_index": INDEX}}))
            bulk.append(line)
        body = "\n".join(bulk) + "\n"
        try:
            r = httpx.post(f"{ES_URL}/_bulk", content=body.encode(),
                headers={"Content-Type": "application/x-ndjson"}, timeout=30)
            print(f"  {f.name}: {len(lines)} records — {'ERR' if r.json().get('errors') else 'OK'}")
            total += len(lines)
        except Exception as e:
            print(f"  {f.name}: FAILED — {e}")
    print(f"\n  Total ingested: {total} records")
    print("  Kibana > Stack Management > Index Patterns > mcp-gateway-audit* > @timestamp")

if __name__ == "__main__":
    run()
