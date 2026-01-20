#!/usr/bin/env python3
"""
Run this locally to find your sensor IDs.
Usage: python list_sensors.py
"""

import os
import requests

# Set these or use environment variables
VIVINT_USERNAME = os.environ.get("VIVINT_USERNAME", "your_email@example.com")
VIVINT_PASSWORD = os.environ.get("VIVINT_PASSWORD", "your_password")

BASE_URL = "https://www.vivintsky.com"


def main():
    print("Logging in to Vivint...")
    resp = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": VIVINT_USERNAME, "password": VIVINT_PASSWORD}
    )
    resp.raise_for_status()
    cookies = resp.cookies

    print("Fetching system info...")
    auth_resp = requests.get(f"{BASE_URL}/api/authuser", cookies=cookies)
    auth_data = auth_resp.json()

    for system in auth_data.get("u", {}).get("system", []):
        panel_id = system.get("panid")
        print(f"\n{'='*60}")
        print(f"Panel: {system.get('sn', 'Unknown')} (ID: {panel_id})")
        print('='*60)

        details_resp = requests.get(f"{BASE_URL}/api/systems/{panel_id}", cookies=cookies)
        details = details_resp.json()

        partitions = details.get("system", {}).get("par", [])
        if partitions:
            arm_state = partitions[0].get("arm", 0)
            arm_labels = {0: "DISARMED", 1: "ARMED STAY", 2: "ARMED AWAY"}
            print(f"Status: {arm_labels.get(arm_state, f'UNKNOWN({arm_state})')}")

        devices = partitions[0].get("d", []) if partitions else []

        print(f"\n{'Sensors:':-<60}")
        print(f"{'ID':<12} {'Name':<25} {'Status':<15}")
        print("-" * 52)

        for d in devices:
            if d.get("t") == "wireless_sensor":
                bypassed = "BYPASSED" if d.get("b", 0) != 0 else "active"
                print(f"{d.get('_id'):<12} {d.get('n', 'Unknown'):<25} {bypassed:<15}")

        print(f"\n{'Locks:':-<60}")
        print(f"{'ID':<12} {'Name':<25} {'Status':<15}")
        print("-" * 52)

        for d in devices:
            if d.get("t") == "door_lock_device":
                locked = "LOCKED" if d.get("s") else "UNLOCKED"
                print(f"{d.get('_id'):<12} {d.get('n', 'Unknown'):<25} {locked:<15}")


if __name__ == "__main__":
    main()
