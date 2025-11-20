#!/usr/bin/env python3
"""
Example: Query scores from Platform API
"""

import requests
import json


def query_scores(token: str, risk_min: float = None, cursor: str = None):
    """Query scores from platform"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    params = {}
    if risk_min:
        params["risk_min"] = risk_min
    if cursor:
        params["cursor"] = cursor

    response = requests.get(
        "http://localhost:8000/api/v1/scores",
        headers=headers,
        params=params
    )

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None


if __name__ == "__main__":
    # In production, get token from OAuth2 flow
    # For demo, you may need to disable auth or use a test token
    token = "test-token"  # Replace with actual OAuth2 token

    # Query high-risk processes
    print("Querying high-risk processes (risk >= 50)...")
    result = query_scores(token, risk_min=50.0)

    if result:
        print(f"\nFound {len(result['data'])} high-risk processes:")
        for score in result['data']:
            print(
                f"  Process {score['process_id']}: "
                f"Risk={score['risk_score']:.1f} "
                f"(calculated at {score['calculated_at']})"
            )

        # Pagination
        if result['pagination']['has_more']:
            print(f"\nMore results available. Cursor: {result['pagination']['cursor']}")

