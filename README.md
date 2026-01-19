# OOM Tracker

Proactive memory monitoring tool that prevents system OOM (Out-Of-Memory) crashes by automatically killing browser processes when memory usage exceeds configured thresholds.

## Table of Contents

- [Problem Statement](#problem-statement)
- [Features](#features)
- [Quick Start](#quick-start)
- [Use Cases](#use-cases)
- [Finding the True Root Cause of OOM Events](#finding-the-true-root-cause-of-oom-events)
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
  - [Memory Snapshot Daemon](#memory-snapshot-daemon)
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

### Memory Snapshot Daemon (NEW in v1.7.0)
- Continuous memory state logging every 30 seconds
- Captures top 20 memory consumers with OOM scores
- Tracks memory growth patterns to detect leaks
- Correlates OOM events with actual memory usage
- Identifies true root cause vs what kernel killed
- Runs as systemd user service for persistence

### Command-Line Tools
- **Memory Status Check** - View current memory usage and top consumers
- **Browser Listing** - List all running browser instances with memory details
- **OOM Analysis** - Analyze historical dmesg logs to identify past OOM events and root causes
- **Snapshot Analysis** - Analyze memory trends and correlate with OOM events
- **Service Management** - Enable, disable, check status, and view logs directly from the tool
- **Flexible Configuration** - Override config file settings via command-line arguments

## Quick Start

```bash
# 1. Check current memory status
python3 ~/Utils/oom-tracker/memory_monitor.py --check

# 2. Test in dry-run mode
python3 ~/Utils/oom-tracker/memory_monitor.py --dry-run --threshold 50

# 3. Enable automated monitoring (kills browsers when memory is high)
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-service

# 4. Enable memory snapshot daemon (tracks true OOM causes)
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-snapshot-daemon

# 5. Monitor the logs
python3 ~/Utils/oom-tracker/memory_monitor.py --logs
```

### After an OOM Event or Reboot

```bash
# Find the TRUE culprit (not just what was killed)
python3 ~/Utils/oom-tracker/memory_monitor.py --correlate-oom

# See memory trends leading up to the event
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-snapshots 120
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

## Finding the True Root Cause of OOM Events

### The Problem

When the Linux OOM killer activates, it often kills small processes (like `gsd-power` at 3MB) instead of the actual memory hog. This happens because:

1. The OOM killer uses a scoring algorithm that considers process age, OOM score adjustments, and other factors - not just memory usage
2. By the time the kernel logs the OOM event, the real culprit may have already released memory or been killed
3. System logs only capture a snapshot at the moment of OOM, missing the buildup

**Example of misleading OOM data:**
```
OOM killed: xdg-desktop-por (2.2 MB)
Top consumers at OOM time: Xwayland (8 MB), tor (7 MB)
```

These tiny processes couldn't have caused OOM on a 32GB system. The real culprit was already gone.

### The Solution: Continuous Memory Snapshots

The memory snapshot daemon captures system state every 30 seconds, so you can see what was *actually* consuming memory before OOM events occur.

### Step-by-Step Methodology

#### Step 1: Enable Continuous Memory Snapshot Logging

```bash
# Option A: Run as a systemd user service (recommended - survives reboots)
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-snapshot-daemon

# Option B: Run manually in background
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot &
```

The daemon logs memory snapshots to `logs/memory-snapshots.jsonl` every 30 seconds (configurable).

#### Step 2: Wait for OOM Event or Reboot

Continue using your system normally. When an OOM event or unexpected reboot occurs, the snapshot data will be available for analysis.

#### Step 3: Correlate OOM Events with Snapshots

After an OOM event, run:

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --correlate-oom
```

**Example output:**
```
======================================================================
OOM EVENT #1
======================================================================
Time:    2025-01-15T03:42:36+0000
Killed:  gsd-power (PID 5688)

Closest snapshot: 2025-01-15T03:42:12 (24s before OOM)
System state: Mem 98.2%, Swap 87.3%

Actual memory consumers at time of OOM:
 #  Process                    Memory MB     Swap MB   OOM Score
--- ------------------------- ------------ ---------- ----------
 1  claude                         2847.3      512.4        738
 2  chrome                         1523.8      234.1        801
 3  code                            892.4      156.2        650
→4  gsd-power                         3.1        0.0        200

--- ROOT CAUSE ANALYSIS ---
MISMATCH: OOM killed gsd-power (3 MB)
          But claude was using 2847 MB
          → TRUE CULPRIT was likely claude
```

#### Step 4: Analyze Memory Trends

To see memory growth patterns and identify leaking processes:

```bash
# Analyze last 60 minutes of snapshots
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-snapshots 60

# Analyze last 2 hours
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-snapshots 120
```

**Example output:**
```
======================================================================
TOP MEMORY CONSUMERS (by average)
======================================================================
 #  Process              Avg MB     Max MB    Swap MB   OOM Score     Growth
--- -------------------- ---------- ---------- ---------- ---------- ----------
 1  claude                 1847.3     2847.3      512.4        738      +1200
 2  chrome                  892.4     1523.8      234.1        801       +631
 3  code                    654.2      892.4      156.2        650       +238

======================================================================
PROCESSES WITH SIGNIFICANT MEMORY GROWTH (>100MB)
======================================================================
  claude                    grew by +1200 MB (1647 MB → 2847 MB)
  chrome                    grew by +631 MB (892 MB → 1523 MB)
```

#### Step 5: Take Action

Once you identify the true culprit:

1. **Adjust OOM scores** to make the culprit more likely to be killed:
   ```bash
   echo 1000 | sudo tee /proc/<PID>/oom_score_adj
   ```

2. **Lower the memory threshold** in `config.yaml` to kill browsers earlier:
   ```yaml
   memory_threshold_percent: 85  # instead of 90
   ```

3. **Protect critical session processes**:
   ```bash
   sudo python3 memory_monitor.py --protect-session
   ```

### Snapshot Daemon Management

```bash
# Check if snapshot daemon is running
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot-status

# View daemon logs
journalctl --user -u oom-tracker-snapshot -f

# Stop the snapshot daemon
python3 ~/Utils/oom-tracker/memory_monitor.py --disable-snapshot-daemon

# Change snapshot interval (default: 30 seconds)
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot --snapshot-interval 15
```

### Quick Reference

| Command | Purpose |
|---------|---------|
| `--snapshot` | Start continuous memory snapshot logging |
| `--snapshot-interval N` | Set interval in seconds (default: 30) |
| `--enable-snapshot-daemon` | Run as systemd user service |
| `--disable-snapshot-daemon` | Stop the service |
| `--snapshot-status` | Check daemon status |
| `--analyze-snapshots N` | Analyze last N minutes of snapshots |
| `--correlate-oom` | Match OOM events to snapshots |

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

### Memory Snapshot Daemon (NEW in v1.7.0)

The memory snapshot daemon continuously logs system memory state to help identify the true root cause of OOM events.

#### Start Snapshot Logging

```bash
# Run as a systemd user service (recommended)
python3 ~/Utils/oom-tracker/memory_monitor.py --enable-snapshot-daemon

# Or run manually (foreground)
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot

# Run with custom interval (default: 30 seconds)
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot --snapshot-interval 15
```

#### Analyze Snapshots

```bash
# Analyze memory trends from last 60 minutes (default)
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-snapshots

# Analyze last 2 hours
python3 ~/Utils/oom-tracker/memory_monitor.py --analyze-snapshots 120
```

**Output includes:**
- Top memory consumers by average usage
- Memory growth patterns (potential leaks)
- OOM kill predictions vs actual memory hogs
- System memory trends over time

#### Correlate OOM Events with Snapshots

After an OOM event or reboot, find the true culprit:

```bash
python3 ~/Utils/oom-tracker/memory_monitor.py --correlate-oom
```

**This shows:**
- Exact timestamp of each OOM event
- What process was killed vs what was actually using memory
- Memory state from the closest snapshot before OOM
- Root cause analysis identifying mismatches

#### Manage Snapshot Daemon

```bash
# Check daemon status
python3 ~/Utils/oom-tracker/memory_monitor.py --snapshot-status

# Stop the daemon
python3 ~/Utils/oom-tracker/memory_monitor.py --disable-snapshot-daemon

# View daemon logs
journalctl --user -u oom-tracker-snapshot -f
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
| `--list-tabs` | List all browser tabs with memory usage |
| **Memory Snapshots (NEW v1.7.0)** | |
| `--snapshot` | Start continuous memory snapshot logging |
| `--snapshot-interval N` | Interval between snapshots in seconds (default: 30) |
| `--analyze-snapshots [MIN]` | Analyze snapshots from last N minutes (default: 60) |
| `--correlate-oom` | Match OOM events with snapshots to find true culprit |
| `--enable-snapshot-daemon` | Run snapshot logging as systemd user service |
| `--disable-snapshot-daemon` | Stop the snapshot daemon |
| `--snapshot-status` | Show snapshot daemon status |
| **OOM Analysis** | |
| `--analyze-oom [DAYS]` | Analyze journalctl for OOM events (default: 7 days) |
| `--show-oom-scores` | Show OOM scores for all running processes |
| `--protect-session` | Protect critical session processes from OOM killer (needs sudo) |
| **Legacy Analysis** | |
| `--analyze-dmesg PATH` | Analyze dmesg log file for OOM events |
| **Configuration** | |
| `--dry-run` | Test mode - log actions without killing processes |
| `--threshold N` | Override memory threshold (0-100) |
| `--swap-threshold N` | Override swap threshold (0-100) |
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
├── memory_monitor.py              # Main Python script
├── config.yaml                    # Configuration file
├── requirements.txt               # Python dependencies
├── oom-tracker-snapshot.service   # Snapshot daemon service template
├── logs/                          # Log directory
│   ├── memory-monitor.log         # Main log file
│   └── memory-snapshots.jsonl     # Memory snapshot data (JSONL format)
└── README.md                      # This file

~/.config/systemd/user/
├── oom-tracker.service            # Systemd service unit (proactive killing)
├── oom-tracker.timer              # Systemd timer unit
└── oom-tracker-snapshot.service   # Snapshot daemon service (if enabled)
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

### Version 1.7.0 (Current)
- **NEW**: Memory snapshot daemon for tracking true OOM root causes
  - `--snapshot` starts continuous memory snapshot logging
  - `--snapshot-interval N` configures logging interval (default: 30s)
  - `--enable-snapshot-daemon` runs as systemd user service
  - `--disable-snapshot-daemon` stops the snapshot service
  - `--snapshot-status` shows daemon status and snapshot file info
- **NEW**: Snapshot analysis tools
  - `--analyze-snapshots [MIN]` analyzes memory trends over time
  - `--correlate-oom` matches OOM events with snapshots to identify true culprits
  - Shows memory growth patterns to detect leaking processes
  - Compares "what was killed" vs "what was actually using memory"
- Enhanced `--analyze-oom` with ISO timestamp support for precise timing
- Added comprehensive methodology documentation for OOM root cause analysis

### Version 1.6.1
- Added swap threshold triggering and detailed process reporting
- Shows swap usage alongside memory in all reports
- Process details include start time and elapsed runtime

### Version 1.5.0
- Added swap monitoring and reboot correlation to OOM analysis
- `--analyze-oom` now shows system reboots alongside OOM events

### Version 1.4.0
- Added tab-level killing strategy (Strategy B)
- `--list-tabs` shows all browser tabs with memory usage
- Config option `kill_mode: tab` kills individual tabs before entire browser

### Version 1.3.0
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
