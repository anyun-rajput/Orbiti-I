
import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

scan_id = 4983  # or make this configurable if needed
isinventoryscan = False
api_url = f"http://localhost:3000/api/scans/{scan_id}?isinventoryscan={str(isinventoryscan).lower()}"
print(api_url)
access_token = os.getenv("API_ACCESS_TOKEN", "")
if not access_token:
    print("API_ACCESS_TOKEN environment variable not set. Skipping scan data store.")
headers = {
    "accept": "application/json",
    "Authorization": f"Bearer {access_token}"
}
try:
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        print(f"Scan Result store successfully: {response.status_code}")
    else:
        print(f"Failed to fetch scan data: {response.status_code} {response.text}")
except Exception as e:
    print(f"Exception while storing scan data: {e}")