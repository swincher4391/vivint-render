# Vivint Sensor Bypass Service

Automatically bypasses a faulty door sensor on your Vivint system. Runs on Render free tier.

## Setup

### 1. Find Your Sensor ID

Run locally to list all sensors and their IDs:

```bash
# Set credentials
export VIVINT_USERNAME="your_email@example.com"
export VIVINT_PASSWORD="your_password"

# List sensors
python list_sensors.py
```

Note the ID of the sensor you want to bypass (e.g., "Back Door").

### 2. Deploy to Render

1. Push this repo to GitHub
2. Go to [Render Dashboard](https://dashboard.render.com)
3. Click "New" → "Blueprint" → Connect your repo
4. Set environment variables:
   - `VIVINT_USERNAME`: Your Vivint login email
   - `VIVINT_PASSWORD`: Your Vivint password
   - `VIVINT_SENSOR_ID`: The sensor ID from step 1
   - `VIVINT_SENSOR_NAME`: Sensor name (fallback if ID not set)

### 3. Verify

After deployment, visit:
- `https://your-app.onrender.com/` - Service status
- `https://your-app.onrender.com/sensors` - List all sensors
- `https://your-app.onrender.com/status` - Panel arm state and sensor status
- `https://your-app.onrender.com/bypass` - Manually trigger bypass
- `https://your-app.onrender.com/enable` - Remove bypass

## How It Works

- Checks every 15 minutes and bypasses the specified sensor if not already bypassed
- Keep-alive ping every 10 minutes prevents Render free tier from sleeping
- Runs bypass immediately on startup

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `/` | Service status and last operation |
| `/health` | Health check |
| `/sensors` | List all sensors with IDs |
| `/status` | Panel arm state and sensor details |
| `/bypass` | Manually trigger bypass |
| `/enable` | Manually remove bypass |
