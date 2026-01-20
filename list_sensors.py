#!/usr/bin/env python3
"""
Run this locally to find your sensor IDs.
Usage: python list_sensors.py
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import urllib.parse
import requests

# Set these or use environment variables
VIVINT_USERNAME = os.environ.get("VIVINT_USERNAME", "your_email@example.com")
VIVINT_PASSWORD = os.environ.get("VIVINT_PASSWORD", "your_password")

AUTH_ENDPOINT = "https://id.vivint.com"
API_ENDPOINT = "https://www.vivintsky.com/api"


class VivintAuth:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Vivint/8.5.0 (iPhone; iOS 17.0)"
        self.mfa_pending = False
        self.mfa_type = None
        self._code_verifier = None
        self._oauth_state = None
        self._redirect_uri = "vivint://app/oauth_redirect"
        self.refresh_token = None

    def _generate_pkce(self):
        """Generate PKCE code verifier and challenge."""
        self._code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(self._code_verifier.encode()).digest()
        self._code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
        self._oauth_state = secrets.token_urlsafe(16)

    def login(self):
        """OAuth2 PKCE login flow."""
        print("Logging in to Vivint...")

        # Step 1: Generate PKCE challenge
        self._generate_pkce()

        # Step 2: Start OAuth flow - this sets CSRF cookies
        self._redirect_uri = "vivint://app/oauth_redirect"
        auth_params = {
            "response_type": "code",
            "client_id": "ios",
            "redirect_uri": self._redirect_uri,
            "scope": "openid email devices email_verified",
            "state": self._oauth_state,
            "code_challenge": self._code_challenge,
            "code_challenge_method": "S256"
        }

        auth_resp = self.session.get(
            f"{AUTH_ENDPOINT}/oauth2/auth",
            params=auth_params,
            allow_redirects=False
        )

        print(f"OAuth init status: {auth_resp.status_code}")

        # Follow redirect to login page to get CSRF cookie
        if auth_resp.status_code == 302:
            login_url = auth_resp.headers.get("Location")
            if login_url:
                if login_url.startswith("/"):
                    login_url = f"{AUTH_ENDPOINT}{login_url}"
                login_resp = self.session.get(login_url, allow_redirects=True)
                print(f"Login page status: {login_resp.status_code}")

        print(f"Cookies received: {list(self.session.cookies.keys())}")

        # Step 3: Submit credentials (cookies are automatically included by session)
        submit_resp = self.session.post(
            f"{AUTH_ENDPOINT}/idp/api/submit",
            params={"client_id": "ios"},
            json={
                "username": self.username,
                "password": self.password
            },
            allow_redirects=False
        )

        print(f"Credential submit status: {submit_resp.status_code}")

        if submit_resp.status_code == 200:
            data = submit_resp.json()

            # Check for MFA requirement (can be "mfa" or "validate")
            if "mfa" in data or data.get("validate") == True:
                self.mfa_pending = True
                mfa_info = data.get("mfa", {})
                self.mfa_type = mfa_info.get("type", "code")
                print(f"\n*** MFA Required ***")
                print("A verification code has been sent to your phone/email.")
                return False

            # Check for redirect URL (success without MFA)
            if "url" in data:
                return self._follow_redirect(data["url"])

            print(f"Unexpected response: {json.dumps(data, indent=2)[:500]}")
            return False

        elif submit_resp.status_code == 302:
            location = submit_resp.headers.get("Location", "")
            return self._extract_and_exchange_code(location)

        print(f"Unexpected response: {submit_resp.text[:500]}")
        return False

    def verify_mfa(self, code):
        """Submit MFA verification code."""
        print(f"Verifying MFA code...")

        resp = self.session.post(
            f"{AUTH_ENDPOINT}/idp/api/validate",
            params={"client_id": "ios"},
            json={
                "code": code,
                "username": self.username,
                "password": self.password
            },
            allow_redirects=False
        )

        print(f"MFA verify status: {resp.status_code}")

        if resp.status_code == 200:
            data = resp.json()
            if "url" in data:
                return self._follow_redirect(data["url"])

        print(f"MFA response: {resp.text[:500]}")
        return False

    def _follow_redirect(self, url):
        """Follow redirect URL to get auth code."""
        if url.startswith("/"):
            url = f"{AUTH_ENDPOINT}{url}"

        resp = self.session.get(url, allow_redirects=False)
        print(f"Redirect status: {resp.status_code}")

        if resp.status_code == 302:
            location = resp.headers.get("Location", "")
            return self._extract_and_exchange_code(location)
        elif resp.status_code == 200:
            data = resp.json()
            if "location" in data:
                return self._extract_and_exchange_code(data["location"])

        print(f"Redirect response: {resp.text[:300]}")
        return False

    def _extract_and_exchange_code(self, location):
        """Extract auth code from redirect and exchange for tokens."""
        print(f"Processing callback...")

        parsed = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" not in params:
            print(f"No auth code in: {location}")
            return False

        auth_code = params["code"][0]
        return self._exchange_token(auth_code)

    def _exchange_token(self, auth_code):
        """Exchange authorization code for access token."""
        print("Exchanging code for token...")

        resp = self.session.post(
            f"{AUTH_ENDPOINT}/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": "ios",
                "redirect_uri": self._redirect_uri,
                "code_verifier": self._code_verifier
            }
        )

        print(f"Token exchange status: {resp.status_code}")

        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data.get("access_token")
            self.refresh_token = token_data.get("refresh_token")

            if access_token:
                self.session.headers["Authorization"] = f"Bearer {access_token}"
                print("Authentication successful!")
                return True

        print(f"Token exchange failed: {resp.text[:500]}")
        return False

    def get_system_info(self):
        """Get panel and device information."""
        resp = self.session.get(f"{API_ENDPOINT}/authuser")
        if resp.status_code == 200:
            return resp.json()
        print(f"Failed to get system info: {resp.status_code} - {resp.text[:200]}")
        return None

    def get_panel_details(self, panel_id):
        """Get detailed device list for a panel."""
        resp = self.session.get(f"{API_ENDPOINT}/systems/{panel_id}")
        if resp.status_code == 200:
            return resp.json()
        return None


def list_sensors(auth):
    """List all sensors with their IDs."""
    auth_data = auth.get_system_info()
    if not auth_data:
        return

    for system in auth_data.get("u", {}).get("system", []):
        panel_id = system.get("panid")
        print(f"\n{'='*60}")
        print(f"Panel: {system.get('sn', 'Unknown')} (ID: {panel_id})")
        print('='*60)

        details = auth.get_panel_details(panel_id)
        if not details:
            continue

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


def main():
    auth = VivintAuth(VIVINT_USERNAME, VIVINT_PASSWORD)

    if not auth.login():
        if auth.mfa_pending:
            code = input("\nEnter your MFA code: ").strip()
            if not auth.verify_mfa(code):
                print("MFA verification failed")
                sys.exit(1)
        else:
            print("Login failed")
            sys.exit(1)

    list_sensors(auth)

    # Output refresh token for Render deployment
    if auth.refresh_token:
        print("\n" + "="*60)
        print("REFRESH TOKEN FOR RENDER")
        print("="*60)
        print("Add this as VIVINT_REFRESH_TOKEN environment variable on Render:\n")
        print(auth.refresh_token)
        print("\n" + "="*60)


if __name__ == "__main__":
    main()
