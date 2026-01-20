"""
Vivint Sensor Bypass Service
Runs on Render and bypasses a faulty sensor on a schedule.
"""

import os
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
BASE_URL = "https://www.vivintsky.com"
VIVINT_USERNAME = os.environ.get("VIVINT_USERNAME")
VIVINT_PASSWORD = os.environ.get("VIVINT_PASSWORD")
SENSOR_ID = os.environ.get("VIVINT_SENSOR_ID")  # Set after running list_sensors locally
SENSOR_NAME = os.environ.get("VIVINT_SENSOR_NAME", "Back Door")  # Fallback to name matching

# Track last operation
last_operation = {
    "timestamp": None,
    "status": "not_run",
    "message": None
}


def login():
    """Authenticate and return session cookies."""
    resp = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": VIVINT_USERNAME, "password": VIVINT_PASSWORD}
    )
    resp.raise_for_status()
    return resp.cookies


def get_system_info(cookies):
    """Get panel and device information."""
    resp = requests.get(f"{BASE_URL}/api/authuser", cookies=cookies)
    resp.raise_for_status()
    return resp.json()


def get_panel_details(panel_id, cookies):
    """Get detailed device list for a panel."""
    resp = requests.get(f"{BASE_URL}/api/systems/{panel_id}", cookies=cookies)
    resp.raise_for_status()
    return resp.json()


def bypass_sensor(panel_id, partition_id, sensor_id, cookies, bypass=True):
    """Bypass or enable a sensor."""
    resp = requests.put(
        f"{BASE_URL}/api/{panel_id}/{partition_id}/sensors/{sensor_id}",
        json={"_id": sensor_id, "b": 1 if bypass else 0},
        cookies=cookies
    )
    resp.raise_for_status()
    return resp.json()


def get_panel_state(cookies):
    """Get current panel arm state."""
    auth_data = get_system_info(cookies)
    for system in auth_data.get("u", {}).get("system", []):
        panel_id = system.get("panid")
        details = get_panel_details(panel_id, cookies)
        partitions = details.get("system", {}).get("par", [])
        if partitions:
            # arm state: 0=disarmed, 1=armed stay, 2=armed away
            return partitions[0].get("arm", 0)
    return 0


def run_bypass():
    """Main bypass operation - runs on schedule."""
    global last_operation

    logger.info("Starting bypass check...")

    try:
        if not VIVINT_USERNAME or not VIVINT_PASSWORD:
            raise ValueError("Vivint credentials not configured")

        cookies = login()
        auth_data = get_system_info(cookies)

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = get_panel_details(panel_id, cookies)

            partitions = details.get("system", {}).get("par", [])
            if not partitions:
                continue

            partition_id = partitions[0].get("_id")
            arm_state = partitions[0].get("arm", 0)
            devices = partitions[0].get("d", [])

            for device in devices:
                # Match by ID or name
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
                        bypass_sensor(panel_id, partition_id, device["_id"], cookies, bypass=True)
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


def list_all_sensors():
    """List all sensors - useful for finding sensor IDs."""
    try:
        cookies = login()
        auth_data = get_system_info(cookies)
        sensors = []

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = get_panel_details(panel_id, cookies)
            devices = details.get("system", {}).get("par", [{}])[0].get("d", [])

            for d in devices:
                if d.get("t") == "wireless_sensor":
                    sensors.append({
                        "id": d.get("_id"),
                        "name": d.get("n"),
                        "bypassed": d.get("b", 0) != 0
                    })

        return sensors
    except Exception as e:
        logger.error(f"Failed to list sensors: {e}")
        return []


# Flask routes
@app.route("/")
def home():
    return jsonify({
        "service": "Vivint Sensor Bypass",
        "status": "running",
        "last_operation": last_operation
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route("/bypass")
def trigger_bypass():
    """Manually trigger bypass."""
    run_bypass()
    return jsonify(last_operation)


@app.route("/enable")
def trigger_enable():
    """Manually remove bypass (for testing)."""
    global last_operation
    try:
        cookies = login()
        auth_data = get_system_info(cookies)

        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = get_panel_details(panel_id, cookies)
            partitions = details.get("system", {}).get("par", [])
            if not partitions:
                continue

            partition_id = partitions[0].get("_id")
            devices = partitions[0].get("d", [])

            for device in devices:
                match = False
                if SENSOR_ID and str(device.get("_id")) == str(SENSOR_ID):
                    match = True
                elif device.get("n", "").lower() == SENSOR_NAME.lower():
                    match = True

                if match:
                    bypass_sensor(panel_id, partition_id, device["_id"], cookies, bypass=False)
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


@app.route("/sensors")
def sensors():
    """List all sensors with IDs."""
    return jsonify(list_all_sensors())


@app.route("/status")
def status():
    """Get current panel and sensor status."""
    try:
        cookies = login()
        auth_data = get_system_info(cookies)

        result = []
        for system in auth_data.get("u", {}).get("system", []):
            panel_id = system.get("panid")
            details = get_panel_details(panel_id, cookies)
            partitions = details.get("system", {}).get("par", [])

            if partitions:
                arm_state = partitions[0].get("arm", 0)
                arm_labels = {0: "disarmed", 1: "armed_stay", 2: "armed_away"}

                result.append({
                    "panel_id": panel_id,
                    "arm_state": arm_labels.get(arm_state, f"unknown({arm_state})"),
                    "sensors": list_all_sensors()
                })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)})


# Initialize scheduler
scheduler = BackgroundScheduler()

# Run bypass check every 15 minutes
scheduler.add_job(func=run_bypass, trigger="interval", minutes=15, id="bypass_job")

# Keep-alive ping every 10 minutes
scheduler.add_job(func=keep_alive, trigger="interval", minutes=10, id="keepalive_job")

scheduler.start()

# Run immediately on startup
run_bypass()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
