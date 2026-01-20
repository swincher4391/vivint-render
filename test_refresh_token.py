#!/usr/bin/env python3
"""
Test that the refresh token works for authentication.
Usage:
  $env:VIVINT_REFRESH_TOKEN = "your_token_here"
  python test_refresh_token.py
"""

import os
import requests

AUTH_ENDPOINT = "https://id.vivint.com"
API_ENDPOINT = "https://www.vivintsky.com/api"

REFRESH_TOKEN = os.environ.get("VIVINT_REFRESH_TOKEN")


def main():
    if not REFRESH_TOKEN:
        print("ERROR: VIVINT_REFRESH_TOKEN environment variable not set")
        print("\nSet it with:")
        print('  $env:VIVINT_REFRESH_TOKEN = "your_token_here"')
        return

    print("Testing refresh token authentication...")
    print(f"Token (first 20 chars): {REFRESH_TOKEN[:20]}...")

    session = requests.Session()
    session.headers["User-Agent"] = "Vivint/8.5.0 (iPhone; iOS 17.0)"

    # Try to get new access token using refresh token
    resp = session.post(
        f"{AUTH_ENDPOINT}/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": REFRESH_TOKEN,
            "client_id": "ios"
        }
    )

    print(f"\nToken refresh status: {resp.status_code}")

    if resp.status_code == 200:
        token_data = resp.json()
        access_token = token_data.get("access_token")
        new_refresh = token_data.get("refresh_token")

        if access_token:
            print("✓ Refresh token is valid!")
            print(f"✓ Got new access token: {access_token[:20]}...")

            if new_refresh and new_refresh != REFRESH_TOKEN:
                print(f"\n⚠ NEW REFRESH TOKEN ISSUED - Use this one for Render:")
                print(new_refresh)

            # Test API access
            session.headers["Authorization"] = f"Bearer {access_token}"
            api_resp = session.get(f"{API_ENDPOINT}/authuser")

            print(f"\nAPI test status: {api_resp.status_code}")

            if api_resp.status_code == 200:
                data = api_resp.json()
                systems = data.get("u", {}).get("system", [])
                print(f"✓ API access works! Found {len(systems)} panel(s)")

                for system in systems:
                    print(f"  - Panel: {system.get('sn', 'Unknown')}")

                print("\n" + "="*50)
                print("SUCCESS! Refresh token is working correctly.")
                print("You can use this token on Render.")
                print("="*50)
            else:
                print(f"✗ API access failed: {api_resp.text[:200]}")
        else:
            print("✗ No access token in response")
    else:
        print(f"✗ Refresh token failed: {resp.text[:300]}")
        print("\nThe token may be expired. Run list_sensors.py again to get a new one.")


if __name__ == "__main__":
    main()
