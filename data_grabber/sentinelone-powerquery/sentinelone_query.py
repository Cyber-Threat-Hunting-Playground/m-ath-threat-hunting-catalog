import json
import os
import requests
import argparse
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed.
warnings.simplefilter('ignore', InsecureRequestWarning)

# Load configuration: env vars (GitHub Actions) take precedence over config.json
def _load_config():
    config = {}
    # Try config.json first (for local/Codespaces)
    config_path = os.environ.get("SENTINELONE_CONFIG", "config.json")
    if os.path.isfile(config_path):
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except Exception:
            pass
    # Env vars override (for GitHub Actions - no config file with secrets)
    url = os.environ.get("SENTINELONE_URL") or config.get("url", "")
    token = os.environ.get("SENTINELONE_TOKEN") or config.get("token", "")
    team_emails_raw = os.environ.get("SENTINELONE_TEAM_EMAILS")
    if team_emails_raw:
        try:
            config["TEAM_EMAILS"] = json.loads(team_emails_raw)
        except json.JSONDecodeError:
            config["TEAM_EMAILS"] = [e.strip() for e in team_emails_raw.split(",") if e.strip()]
    return config

config = _load_config()
DATE_FORMAT = config.get("DATE_FORMAT", "%Y-%m-%dT%H:%M:%SZ")
TEAM_EMAILS = config.get("TEAM_EMAILS", [])
DEFAULT_URL = os.environ.get("SENTINELONE_URL") or config.get("url", "")
DEFAULT_TOKEN = os.environ.get("SENTINELONE_TOKEN") or config.get("token", "")

class SentinelOneClient:
    def __init__(self, base_url, token, verify_ssl=False, proxies=None):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.verify_ssl = verify_ssl
        self.proxies = proxies

    def data_lake_search(self, query, start_time="24h", stop_time="1min", priority="low", timeout=120):
        url = f"{self.base_url}/powerQuery"
        payload = {
            "query": query,
            "endTime": stop_time,
            "startTime": start_time,
            "priority": priority,
            "teamEmails": TEAM_EMAILS
        }

        try:
            response = requests.post(
                url,
                headers=self.headers,
                data=json.dumps(payload),
                timeout=timeout,
                verify=self.verify_ssl,
                proxies=self.proxies
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

def run_query(client, query, start_time="24h", stop_time="1min", priority="low", timeout=120):
    success, result = client.data_lake_search(query, start_time, stop_time, priority, timeout)
    if not success:
        return
    columns = [col['name'] for col in result.get('columns', [])]
    values = result.get('values', [])
    table = [dict(zip(columns, row)) for row in values]

    output = {
        "cpuUsage": result.get("cpuUsage"),
        "status": result.get("status"),
        "matchingEvents": result.get("matchingEvents"),
        "omittedEvents": result.get("omittedEvents"),
        "events": table
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SentinelOne Data Lake PowerQuery CLI")
    parser.add_argument('--url', default=DEFAULT_URL, help='Base URL of SentinelOne API')
    parser.add_argument('--token', default=DEFAULT_TOKEN, help='Bearer token for authentication')
    parser.add_argument('--query', required=True, help='PowerQuery string')
    parser.add_argument('--start', default="24h", help='Start time (default: 24h)')
    parser.add_argument('--stop', default="1min", help='Stop time (default: 1min)')
    parser.add_argument('--priority', default="low", help='Query priority (default: low)')
    parser.add_argument('--timeout', type=int, default=120, help='Request timeout in seconds')

    args = parser.parse_args()

    client = SentinelOneClient(
        base_url=args.url,
        token=args.token
    )

    run_query(client, args.query, args.start, args.stop, args.priority, args.timeout)