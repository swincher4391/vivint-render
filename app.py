"""
Vivint Sensor Bypass Service
Runs on Render and bypasses a faulty sensor on a schedule.
"""

import os
import base64
import hashlib
import secrets
import urllib.parse
import logging
from datetime import datetime
from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Vivint API configuration
AUTH_ENDPOINT = "https://id.vivint.com"
API_ENDPOINT = "https://www.vivintsky.com/api"

VIVINT_USERNAME = os.environ.get("VIVINT_USERNAME")
VIVINT_PASSWORD = os.environ.get("VIVINT_PASSWORD")
VIVINT_REFRESH_TOKEN = os.environ.get("VIVINT_REFRESH_TOKEN")  # Get this from list_sensors.py
SENSOR_ID = os.environ.get("VIVINT_SENSOR_ID")
SENSOR_NAME = os.environ.get("VIVINT_SENSOR_NAME", "Back Door")

# Track last operation
last_operation = {
    "timestamp": None,
    "status": "not_run",
    "message": None
}

# Store current session
current_session = {
    "access_token": None,
    "refresh_token": VIVINT_REFRESH_TOKEN
}


class VivintAuth:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Vivint/8.5.0 (iPhone; iOS 17.0)"
        self._redirect_uri = "vivint://app/oauth_redirect"

    def authenticate(self):
        """Authenticate using refresh token (preferred) or username/password."""
        # Try refresh token first
        if current_session.get("refresh_token"):
            logger.info("Attempting refresh token authentication...")
            if self._refresh_token(current_session["refresh_token"]):
                return True
            logger.warning("Refresh token failed, trying password auth...")

        # Fall back to password (will fail if MFA required)
        if VIVINT_USERNAME and VIVINT_PASSWORD:
            return self._password_auth()

        logger.error("No valid authentication method available")
        return False

    def _refresh_token(self, refresh_token):
        """Use refresh token to get new access token."""
        try:
            logger.info(f"Using refresh token (first 20 chars): {refresh_token[:20] if refresh_token else 'None'}...")

            resp = self.session.post(
                f"{AUTH_ENDPOINT}/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": "ios"
                }
            )

            logger.info(f"Token refresh status: {resp.status_code}")

            if resp.status_code == 200:
                token_data = resp.json()
                access_token = token_data.get("access_token")
                new_refresh = token_data.get("refresh_token")

                if access_token:
                    self.session.headers["Authorization"] = f"Bearer {access_token}"
                    current_session["access_token"] = access_token
                    if new_refresh:
                        current_session["refresh_token"] = new_refresh
                    logger.info("Refresh token authentication successful")
                    return True

            logger.error(f"Refresh token failed: {resp.status_code} - {resp.text[:200]}")
            return False
        except Exception as e:
            logger.error(f"Refresh token error: {e}")
            return False

    def _password_auth(self):
        """OAuth2 PKCE login (requires MFA - won't work on Render)."""
        logger.info("Attempting password authentication...")

        # Generate PKCE
        code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
        state = secrets.token_urlsafe(16)

        # Start OAuth flow
        auth_params = {
            "response_type": "code",
            "client_id": "ios",
            "redirect_uri": self._redirect_uri,
            "scope": "openid email devices email_verified",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        }

        auth_resp = self.session.get(
            f"{AUTH_ENDPOINT}/oauth2/auth",
            params=auth_params,
            allow_redirects=False
        )

        if auth_resp.status_code == 302:
            login_url = auth_resp.headers.get("Location", "")
            if login_url.startswith("/"):
                login_url = f"{AUTH_ENDPOINT}{login_url}"
            self.session.get(login_url, allow_redirects=True)

        # Submit credentials
        submit_resp = self.session.post(
            f"{AUTH_ENDPOINT}/idp/api/submit",
            params={"client_id": "ios"},
            json={"username": VIVINT_USERNAME, "password": VIVINT_PASSWORD},
            allow_redirects=False
        )

        if submit_resp.status_code == 200:
            data = submit_resp.json()

            # MFA required - can't proceed automatically
            if "mfa" in data or data.get("validate") == True:
                logger.error("MFA required - please run list_sensors.py locally to get refresh token")
                return False

            # Success - follow redirect
            if "url" in data:
                url = data["url"]
                if url.startswith("/"):
                    url = f"{AUTH_ENDPOINT}{url}"
                redirect_resp = self.session.get(url, allow_redirects=False)

                if redirect_resp.status_code == 302:
                    location = redirect_resp.headers.get("Location", "")
                    parsed = urllib.parse.urlparse(location)
                    params = urllib.parse.parse_qs(parsed.query)

                    if "code" in params:
                        return self._exchange_token(params["code"][0], code_verifier)

        logger.error(f"Password auth failed: {submit_resp.status_code}")
        return False

    def _exchange_token(self, auth_code, code_verifier):
        """Exchange authorization code for tokens."""
        resp = self.session.post(
            f"{AUTH_ENDPOINT}/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "client_id": "ios",
                "redirect_uri": self._redirect_uri,
                "code_verifier": code_verifier
            }
        )

        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")

            if access_token:
                self.session.headers["Authorization"] = f"Bearer {access_token}"
                current_session["access_token"] = access_token
                current_session["refresh_token"] = refresh_token
                logger.info("Token exchange successful")
                return True

        return False

    def get_system_info(self):
        """Get panel and device information."""
        resp = self.session.get(f"{API_ENDPOINT}/authuser")
        if resp.status_code == 200:
            return resp.json()
        logger.error(f"Failed to get system info: {resp.status_code}")
        return None

    def get_panel_details(self, panel_id):
        """Get detailed device list for a panel."""
        resp = self.session.get(f"{API_ENDPOINT}/systems/{panel_id}")
        if resp.status_code == 200:
            return resp.json()
        return None

    def bypass_sensor(self, panel_id, partition_id, sensor_id, bypass=True):
        """Bypass or enable a sensor."""
        # Partition ID may contain pipe character - don't let requests encode it
        url = f"{API_ENDPOINT}/{panel_id}/{partition_id}/sensors/{sensor_id}"
        logger.info(f"Bypass URL: {url}")
        resp = self.session.put(
            url,
            json={"_id": sensor_id, "b": 1 if bypass else 0}
        )
        resp.raise_for_status()
        return resp.json()


def run_bypass():
    """Main bypass operation - runs on schedule."""
    global last_operation

    logger.info("Starting bypass check...")

    try:
        if not VIVINT_REFRESH_TOKEN and not (VIVINT_USERNAME and VIVINT_PASSWORD):
            raise ValueError("No Vivint credentials configured. Set VIVINT_REFRESH_TOKEN.")

        auth = VivintAuth()
        if not auth.authenticate():
            raise ValueError("Authentication failed. Check VIVINT_REFRESH_TOKEN.")

        auth_data = auth.get_system_info()
        if not auth_data:
            raise ValueError("Failed to get system info")

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = auth.get_panel_details(panel_id)

            partitions = details.get("system", {}).get("par", [])
            if not partitions:
                continue

            partition_id_raw = partitions[0].get("_id")
            # Partition ID may be "panelid|num" format - extract just the number
            if isinstance(partition_id_raw, str) and "|" in partition_id_raw:
                partition_id = partition_id_raw.split("|")[1]
            else:
                partition_id = partition_id_raw
            logger.info(f"Panel ID: {panel_id}, Partition ID: {partition_id}")
            arm_state = partitions[0].get("arm", 0)
            devices = partitions[0].get("d", [])

            for device in devices:
                match = False
                if SENSOR_ID and str(device.get("_id")) == str(SENSOR_ID):
                    match = True
                elif device.get("n", "").lower() == SENSOR_NAME.lower():
                    match = True

                if match:
                    current_bypass = device.get("b", 0) != 0
                    sensor_name = device.get("n", "Unknown")

                    if current_bypass:
                        msg = f"Sensor '{sensor_name}' already bypassed. Arm state: {arm_state}"
                        logger.info(msg)
                    else:
                        auth.bypass_sensor(panel_id, partition_id, device["_id"], bypass=True)
                        msg = f"Bypassed sensor '{sensor_name}'. Arm state: {arm_state}"
                        logger.info(msg)

                    last_operation = {
                        "timestamp": datetime.now().isoformat(),
                        "status": "success",
                        "message": msg,
                        "sensor": sensor_name,
                        "was_bypassed": current_bypass,
                        "arm_state": arm_state
                    }
                    return

        last_operation = {
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": f"Sensor not found (ID: {SENSOR_ID}, Name: {SENSOR_NAME})"
        }
        logger.warning(last_operation["message"])

    except Exception as e:
        last_operation = {
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": str(e)
        }
        logger.error(f"Bypass failed: {e}")


def keep_alive():
    """Ping self to prevent Render free tier sleep."""
    render_url = os.environ.get("RENDER_EXTERNAL_URL")
    if render_url:
        try:
            requests.get(f"{render_url}/health", timeout=10)
            logger.debug("Keep-alive ping sent")
        except Exception as e:
            logger.warning(f"Keep-alive ping failed: {e}")


# Flask routes
@app.route("/")
def home():
    return jsonify({
        "service": "Vivint Sensor Bypass",
        "status": "running",
        "schedule": "10PM EST daily",
        "last_operation": last_operation
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route("/debug")
def debug():
    """Debug endpoint to check configuration."""
    return jsonify({
        "refresh_token_set": bool(VIVINT_REFRESH_TOKEN),
        "refresh_token_preview": VIVINT_REFRESH_TOKEN[:20] + "..." if VIVINT_REFRESH_TOKEN else None,
        "sensor_id": SENSOR_ID,
        "sensor_name": SENSOR_NAME,
        "username_set": bool(VIVINT_USERNAME)
    })


@app.route("/bypass")
def trigger_bypass():
    """Manually trigger bypass."""
    run_bypass()
    return jsonify(last_operation)


@app.route("/enable")
def trigger_enable():
    """Manually remove bypass."""
    global last_operation
    try:
        auth = VivintAuth()
        if not auth.authenticate():
            raise ValueError("Authentication failed")

        auth_data = auth.get_system_info()

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = auth.get_panel_details(panel_id)
            partitions = details.get("system", {}).get("par", [])
            if not partitions:
                continue

            partition_id_raw = partitions[0].get("_id")
            if isinstance(partition_id_raw, str) and "|" in partition_id_raw:
                partition_id = partition_id_raw.split("|")[1]
            else:
                partition_id = partition_id_raw
            devices = partitions[0].get("d", [])

            for device in devices:
                match = False
                if SENSOR_ID and str(device.get("_id")) == str(SENSOR_ID):
                    match = True
                elif device.get("n", "").lower() == SENSOR_NAME.lower():
                    match = True

                if match:
                    auth.bypass_sensor(panel_id, partition_id, device["_id"], bypass=False)
                    last_operation = {
                        "timestamp": datetime.now().isoformat(),
                        "status": "success",
                        "message": f"Enabled sensor '{device.get('n')}'"
                    }
                    return jsonify(last_operation)

        last_operation = {
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": "Sensor not found"
        }
        return jsonify(last_operation)

    except Exception as e:
        last_operation = {
            "timestamp": datetime.now().isoformat(),
            "status": "error",
            "message": str(e)
        }
        return jsonify(last_operation)


@app.route("/status")
def status():
    """Get current panel and sensor status."""
    try:
        auth = VivintAuth()
        if not auth.authenticate():
            return jsonify({"error": "Authentication failed"})

        auth_data = auth.get_system_info()
        result = []

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = auth.get_panel_details(panel_id)
            partitions = details.get("system", {}).get("par", [])

            if partitions:
                arm_state = partitions[0].get("arm", 0)
                arm_labels = {0: "disarmed", 1: "armed_stay", 2: "armed_away"}
                devices = partitions[0].get("d", [])

                sensors = [
                    {"id": d.get("_id"), "name": d.get("n"), "bypassed": d.get("b", 0) != 0}
                    for d in devices if d.get("t") == "wireless_sensor"
                ]

                result.append({
                    "panel_id": panel_id,
                    "arm_state": arm_labels.get(arm_state, f"unknown({arm_state})"),
                    "sensors": sensors
                })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})


# Initialize scheduler
scheduler = BackgroundScheduler()

# Run bypass at 10PM every day (Eastern time)
# Render uses UTC, so 10PM EST = 3AM UTC (or 2AM during DST)
scheduler.add_job(func=run_bypass, trigger="cron", hour=3, minute=0, id="bypass_job")

# Keep-alive ping every 10 minutes to prevent Render free tier sleep
scheduler.add_job(func=keep_alive, trigger="interval", minutes=10, id="keepalive_job")

scheduler.start()

logger.info("Scheduler started. Bypass scheduled for 10PM EST daily.")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
