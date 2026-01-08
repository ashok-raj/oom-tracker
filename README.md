# OOM Tracker

Proactive memory monitoring tool that prevents system OOM (Out-Of-Memory) crashes by automatically killing browser processes when memory usage exceeds configured thresholds.

## Table of Contents

- [Problem Statement](#problem-statement)
- [Features](#features)
- [Quick Start](#quick-start)
- [Use Cases](#use-cases)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Start the Monitor](#start-the-monitor)
  - [Stop the Monitor](#stop-the-monitor)
  - [Manual Run](#manual-run)
- [Command-Line Options](#command-line-options)
  - [Check Memory Status](#check-memory-status)
  - [List Running Browsers](#list-running-browsers)
  - [Analyze OOM Events in Logs](#analyze-oom-events-in-logs)
  - [Override Configuration Settings](#override-configuration-settings)
  - [All Available Options](#all-available-options)
- [How It Works](#how-it-works)
- [Safety Features](#safety-features)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Files and Directories](#files-and-directories)
- [Maintenance](#maintenance)
- [Version History](#version-history)
- [Support](#support)

## Problem Statement

Your system was experiencing overnight logouts caused by the Linux OOM killer terminating critical processes when memory usage reached 100%. This tool prevents that by proactively managing memory before the kernel's OOM killer activates.

## Features

### Proactive Monitoring
- Monitors system memory usage every 60 seconds
- Automatically kills the largest browser instance when memory exceeds 90% usage
- Only targets browser processes (Chrome, Firefox, Brave, Edge, Opera, Vivaldi)
- Only affects processes owned by your user account
- Graceful shutdown with SIGTERM (30s timeout) before forcing SIGKILL
- Structured logging to file and systemd journal
- Configurable thresholds and behavior
- Dry-run mode for testing

### Command-Line Tools
- **Memory Status Check** - View current memory usage and top consumers
- **Browser Listing** - List all running browser instances with memory details
- **OOM Analysis** - Analyze historical dmesg logs to identify past OOM events and root causes
- **Service Management** - Enable, disable, check status, and view logs directly from the tool
- **Flexible Configuration** - Override config file settings via command-line arguments

## Quick Start

```bash
# 1. Check current memory status
python3 ~/Utils/oom-tracker/memory_monitor.py --check

# 2. Test in dry-run mode
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run --threshold 50

# 3. Enable automated monitoring
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-service

# 4. Monitor the logs
python3 ~/Utils/oom-tracker/memory_monitor.py --logs
```

## Use Cases

### Prevent System OOM Crashes
Run the automated monitor to prevent browser memory bloat from triggering kernel OOM killer:
- Systemd timer runs check every 60 seconds
- Automatically kills largest browser when memory > 90%
- Prevents critical processes (login sessions, system services) from being killed

### Investigate Past OOM Events
Use the analysis tool to understand why your system crashed or logged you out:
```bash
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /var/log/dmesg.1.gz
```
Identifies root cause processes and helps determine if you need more RAM/swap.

### Monitor Memory Usage
Use check and list commands to understand current memory consumption:
```bash
# Quick memory overview
python3 ~/Utils/oom-tracker/memory_monitor.py --check

# Detailed browser memory breakdown
python3 ~/Utils/oom-tracker/memory_monitor.py --list-browsers
```

### Test Before Production
Use dry-run mode to see what would happen without killing processes:
```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run --threshold 85
```

## Installation

The tool is already installed in `~/Utils/oom-tracker/`. Dependencies (psutil, PyYAML) have been installed system-wide.

## Configuration

Edit `~/Utils/oom-tracker/config.yaml`:

```yaml
memory_threshold_percent: 90        # Kill browsers when memory exceeds this %
kill_timeout_seconds: 30            # Wait time before forcing SIGKILL
log_level: INFO                     # DEBUG, INFO, WARNING, ERROR, CRITICAL
log_max_bytes: 10485760            # 10MB log file size before rotation
log_backup_count: 5                # Keep 5 backup log files
dry_run: false                     # Set to true to test without killing
```

## Usage

### Start the Monitor

```bash
# Enable and start the timer
systemctl --user enable --now oom-tracker.timer

# Check timer status
systemctl --user status oom-tracker.timer

# View upcoming timer triggers
systemctl --user list-timers
```

### Stop the Monitor

```bash
# Stop and disable the timer
systemctl --user disable --now oom-tracker.timer
```

### Manual Run

```bash
# Run the monitor once manually
systemctl --user start oom-tracker.service

# Or run the script directly
python3 ~/Utils/oom-tracker/memory_monitor.py
```

## Command-Line Options

The tool provides several command-line options for monitoring, testing, and analysis:

### View Help

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --help
```

### Check Memory Status

View current memory usage and top consumers without taking any action:

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --check
```

**Output includes:**
- Current memory usage percentage
- Total, used, and available memory
- Top 5 memory-consuming processes
- Comparison against configured threshold

### List Running Browsers

Display all browser instances with detailed memory breakdown:

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --list-browsers
```

**Output includes:**
- Summary by browser type (Chrome, Firefox, etc.)
- Individual browser instances with PID and memory usage
- Process count per browser instance
- Top processes within each browser tree
- Total browser memory usage

### Analyze System OOM Events (NEW in v1.3.0)

Analyze system logs (journalctl) for OOM events with detailed root cause analysis:

```bash
# Analyze OOM events from the last 7 days (default)
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-oom

# Analyze OOM events from the last 3 days
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-oom 3

# Analyze just today
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-oom 1
```

**This command provides:**
- Timeline of all OOM events with timestamps
- Processes that were killed and memory freed
- Top memory consumers at the time of each OOM
- Root cause analysis identifying consistent memory hogs
- Specific recommendations (detects if session processes were killed)
- Warning if critical processes like gnome-shell or nautilus were killed

**Example output:**
```
======================================================================
SYSTEM OOM ANALYSIS - LAST 7 DAYS
======================================================================

⚠ Found 3 OOM event(s)

TIMELINE OF OOM EVENTS
----------------------------------------------------------------------

1. Jan 07 03:19:32
   Killed: chrome (PID 892044) - Freed 384.8 MB
   Triggered by: gnome-shell (PID 720678)

2. Jan 07 03:42:36
   Killed: dropbox (PID 721105) - Freed 183.7 MB

3. Jan 07 03:48:50
   Killed: nautilus (PID 893201) - Freed 135.1 MB
   ⚠  CAUSED LOGOUT - Session process killed!

======================================================================
MOST RECENT OOM EVENT - DETAILED ANALYSIS
======================================================================

[Detailed breakdown of the most recent OOM event]

======================================================================
RECOMMENDATIONS
======================================================================

⚠  CRITICAL: Session processes were killed, causing logout!
   To prevent future logouts:
   1. Run: python3 memory_monitor.py --protect-session
   2. Enable OOM tracker to kill browsers proactively
```

### Protect Session Processes (NEW in v1.3.0)

Configure OOM scores to protect critical session processes and prevent logouts:

```bash
# Run with sudo to protect all session processes
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --protect-session
```

**What this does:**
- Sets negative OOM scores for critical processes (gnome-shell, gnome-session, systemd, dbus-daemon, nautilus)
- Sets high OOM scores (300) for browsers to make them preferred targets
- Prevents the kernel from killing session processes, which would cause logout
- Only affects currently running processes

**Note:** This must be run with sudo to modify system and user session processes.

### Show OOM Scores (NEW in v1.3.0)

View OOM scores for all running processes to understand OOM kill priority:

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --show-oom-scores
```

**Output includes:**
- Top 20 processes most likely to be killed by OOM killer
- List of protected processes (negative scores)
- OOM score guide explaining what each score means

### Analyze OOM Events in Dmesg Logs (v1.1.0)

Analyze gzipped or plain text dmesg logs to find historical OOM killer events:

```bash
# Analyze a specific dmesg log (requires sudo for /var/log files)
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /var/log/dmesg.4.gz

# Analyze current dmesg
sudo dmesg > /tmp/dmesg.txt
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /tmp/dmesg.txt
```

**For each OOM event found, displays:**
- Timestamp of the OOM event
- Process that triggered the OOM killer
- Process that was killed (victim)
- Amount of memory freed
- Top 5 memory consumers at the time of OOM
- Memory statistics (active/inactive memory)

**Summary analysis includes:**
- Processes killed most frequently
- Root cause identification (consistently high memory consumers)
- Recommendations for prevention

**Example output:**
```
============================================================
DMESG OOM ANALYSIS: /var/log/dmesg.4.gz
============================================================

Found 2 OOM event(s)

--- OOM Event #1 ---
Timestamp:       [123.456789]
Triggered by:    chrome (PID 5678)
Killed process:  chrome (PID 5678)
Memory freed:    15625.0 MB (RSS)

Top 5 Memory Consumers at time of OOM:
  1. java                 (PID 1234  ) -   6835.9 MB
  2. chrome               (PID 5678  ) -   3906.2 MB
  3. firefox              (PID 9012  ) -   1953.1 MB
  ...

============================================================
SUMMARY & ROOT CAUSE ANALYSIS
============================================================

Processes killed by OOM:
  chrome: 1 time(s)

Likely root cause (top memory consumers across all events):
  1. java                 - Average 6933.6 MB (present in 2/2 events)
  2. chrome               - Average 3906.2 MB (present in 1/2 events)
  ...

Recommendation: Consider limiting memory usage or adding more RAM/swap
============================================================
```

### Override Configuration Settings

Override config.yaml settings from the command line:

```bash
# Run in dry-run mode (no processes killed)
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run

# Use a different memory threshold (override config)
python3 ~/Utils/oom-tracker/memory_monitor.py --threshold 85

# Combine options
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run --threshold 50

# Use alternate config file
python3 ~/Utils/oom-tracker/memory_monitor.py --config /path/to/custom-config.yaml
```

### Service Management

Manage the systemd service directly from the command line:

```bash
# Enable and start the service
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-service

# Check service status
python3 ~/Utils/oom-tracker/memory_monitor.py --service-status

# View recent logs (last 50 lines)
python3 ~/Utils/oom-tracker/memory_monitor.py --logs

# Follow logs in real-time (Ctrl+C to exit)
python3 ~/Utils/oom-tracker/memory_monitor.py --follow-logs

# Disable and stop the service
python3 ~/Utils/oom-tracker/memory_monitor.py --disable-service
```

These commands are simpler alternatives to using `systemctl` and `journalctl` directly.

### All Available Options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Show help message and exit |
| `--version` | Show version number |
| `--check` | Check memory status and exit (no action taken) |
| `--list-browsers` | List all browser instances and exit |
| **OOM Analysis (NEW v1.3.0)** | |
| `--analyze-oom [DAYS]` | Analyze journalctl for OOM events (default: 7 days) |
| `--show-oom-scores` | Show OOM scores for all running processes |
| `--protect-session` | Protect critical session processes from OOM killer (needs sudo) |
| **Legacy Analysis** | |
| `--analyze-dmesg PATH` | Analyze dmesg log file for OOM events |
| **Configuration** | |
| `--dry-run` | Test mode - log actions without killing processes |
| `--threshold N` | Override memory threshold (0-100) |
| `--config PATH` | Use alternate configuration file |
| **Service Management** | |
| `--enable-service` | Enable and start the systemd timer |
| `--disable-service` | Disable and stop the systemd timer |
| `--service-status` | Show service and timer status |
| `--logs` | View recent logs from the service |
| `--follow-logs` | Follow logs in real-time |

### View Logs

```bash
# View systemd journal logs
journalctl --user -u oom-tracker.service -f

# View log file
tail -f ~/Utils/oom-tracker/logs/memory-monitor.log

# View recent logs
journalctl --user -u oom-tracker.service --since "1 hour ago"
```

## How It Works

1. **Memory Monitoring**: Every 60 seconds, the tool checks system memory using `psutil.virtual_memory()`
2. **Threshold Check**: If memory usage exceeds 90%, it proceeds to kill a browser
3. **Browser Detection**: Scans all processes owned by your user to find browser process trees
4. **Process Tree Aggregation**: Groups browser subprocesses by their parent to calculate total memory per browser instance
5. **Target Selection**: Identifies the browser instance consuming the most memory
6. **Graceful Termination**:
   - Sends SIGTERM to the parent browser process
   - Waits 30 seconds for graceful shutdown (allows session save)
   - If still alive, sends SIGKILL to force termination
7. **Logging**: Records all actions with details about memory freed and top consumers

## Safety Features

- Only monitors processes owned by current user
- Only targets recognized browser processes
- Never touches system or other critical processes
- Filters out zombie processes
- Handles race conditions (process exits before kill)
- Graceful shutdown with configurable timeout
- Comprehensive error handling and logging

## Testing

### Dry Run Mode

Test the tool without actually killing processes:

```bash
# Method 1: Use command-line flag (easiest)
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run --threshold 50

# Method 2: Edit config.yaml
nano ~/Utils/oom-tracker/config.yaml
# Set: dry_run: true
python3 ~/Utils/oom-tracker/memory_monitor.py

# Check what it would have done
tail ~/Utils/oom-tracker/logs/memory-monitor.log
```

### Check Current Status

Before setting up automated monitoring, check current memory status:

```bash
# Check memory and top consumers
python3 ~/Utils/oom-tracker/memory_monitor.py --check

# List browser memory usage
python3 ~/Utils/oom-tracker/memory_monitor.py --list-browsers
```

### Simulate Memory Pressure

```bash
# Install stress tool (if needed)
sudo apt-get install stress

# Create memory pressure (use 80% of available RAM)
stress --vm 1 --vm-bytes $(awk '/MemAvailable/{printf "%d\n", $2 * 0.8}' < /proc/meminfo)k --timeout 60s

# Watch the monitor in action
journalctl --user -u oom-tracker.service -f
```

## Troubleshooting

### Timer not running

```bash
# Check timer status
systemctl --user status oom-tracker.timer

# Reload systemd if you made changes
systemctl --user daemon-reload

# Re-enable the timer
systemctl --user enable --now oom-tracker.timer
```

### No browsers being killed

Check logs to see if:
1. Memory threshold is not being exceeded
2. No browser processes are running
3. Dry-run mode is enabled in config.yaml

```bash
# Check current memory status
python3 ~/Utils/oom-tracker/memory_monitor.py --check

# See what browsers are running
python3 ~/Utils/oom-tracker/memory_monitor.py --list-browsers

# Review logs
tail -50 ~/Utils/oom-tracker/logs/memory-monitor.log
```

### Investigating Past OOM Events

If your system experienced OOM events before installing this tool, analyze historical logs:

```bash
# Check recent dmesg logs for OOM events
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /var/log/dmesg

# Check older rotated logs
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /var/log/dmesg.1.gz
sudo python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-dmesg /var/log/dmesg.2.gz

# This helps identify:
# - Which processes were killed by the kernel OOM killer
# - What processes were using the most memory
# - Root cause of memory pressure
```

### Permission errors

The tool runs as your user and can only kill processes you own. This is by design for safety.

For analyzing dmesg logs, sudo is required to read `/var/log/dmesg*` files.

## Files and Directories

```
~/Utils/oom-tracker/
├── memory_monitor.py       # Main Python script
├── config.yaml            # Configuration file
├── requirements.txt       # Python dependencies
├── logs/                  # Log directory
│   └── memory-monitor.log # Main log file
└── README.md              # This file

~/.config/systemd/user/
├── oom-tracker.service    # Systemd service unit
└── oom-tracker.timer      # Systemd timer unit
```

## Maintenance

### Adjusting Threshold

If 90% is too aggressive or not aggressive enough:

```bash
# Edit config.yaml
nano ~/Utils/oom-tracker/config.yaml

# Change memory_threshold_percent to desired value (e.g., 85 or 95)

# No need to restart - config is reloaded on each run
```

### Log Rotation

Logs automatically rotate when they reach 10MB, keeping 5 backup files. To change:

```bash
# Edit config.yaml
nano ~/Utils/oom-tracker/config.yaml

# Adjust log_max_bytes and log_backup_count
```

### Uninstall

```bash
# Stop and disable the timer
systemctl --user disable --now oom-tracker.timer

# Remove systemd files
rm ~/.config/systemd/user/oom-tracker.{service,timer}

# Remove the tool directory (optional)
rm -rf ~/Utils/oom-tracker

# Reload systemd
systemctl --user daemon-reload
```

## Additional Notes

- The tool successfully prevented your previous OOM crashes by proactively managing memory
- Swap has been increased from 8GB to 16GB to provide additional breathing room
- Monitor your logs for the first few days to ensure appropriate browser killing behavior
- Consider closing browsers manually at night if you frequently trigger the threshold

## Version History

### Version 1.3.0 (Current)
- **NEW**: Added `--analyze-oom [DAYS]` to analyze journalctl logs for OOM events with detailed timeline
  - Automatically queries system logs and provides root cause analysis
  - Detects if session processes were killed (causing logout)
  - Shows timeline of all OOM events with memory freed
  - Provides specific recommendations based on what was killed
- **NEW**: Added `--show-oom-scores` to view OOM scores for all running processes
  - Shows which processes are most/least likely to be killed by OOM
  - Identifies already-protected processes
- **NEW**: Added `--protect-session` to configure OOM score adjustments
  - Protects critical session processes (gnome-shell, gnome-session, systemd, etc.) from OOM killer
  - Increases OOM score for browsers to make them preferred targets
  - Run with sudo to protect all user session processes
- Enhanced root cause analysis across all analysis modes
- Better error handling and permission checking

### Version 1.2.0
- Added built-in service management commands
- Added `--enable-service` to enable and start systemd timer
- Added `--disable-service` to disable and stop systemd timer
- Added `--service-status` to show service and timer status
- Added `--logs` to view recent service logs
- Added `--follow-logs` to watch logs in real-time
- Simplified user experience - no need to remember systemctl/journalctl commands

### Version 1.1.0
- Added command-line interface with argparse
- Added `--check` mode for memory status checking
- Added `--list-browsers` mode for browser memory analysis
- Added `--analyze-dmesg` mode for historical OOM event analysis
- Added `--dry-run`, `--threshold`, and `--config` command-line overrides
- Improved error handling and user feedback
- Added support for analyzing both gzipped and plain text dmesg logs

### Version 1.0.0
- Automated proactive memory monitoring via systemd timer
- Browser process detection and graceful termination
- Configurable thresholds and behavior via YAML config
- Structured logging with rotation

## Support

Check logs for detailed information about any issues:
```bash
journalctl --user -u oom-tracker.service --since today
tail -100 ~/Utils/oom-tracker/logs/memory-monitor.log
```
