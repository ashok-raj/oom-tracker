#!/usr/bin/env python3
"""
OOM Tracker - Proactive Memory Monitor
Prevents system OOM crashes by killing browser processes when memory usage is high.
"""

import os
import sys
import time
import json
import logging
import argparse
import gzip
import re
import subprocess
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import psutil
import yaml
import signal


# Configuration
VERSION = '1.7.0'
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / 'config.yaml'
LOG_DIR = SCRIPT_DIR / 'logs'
LOG_FILE = LOG_DIR / 'memory-monitor.log'
SNAPSHOT_FILE = LOG_DIR / 'memory-snapshots.jsonl'

# Browser detection patterns
BROWSER_PATTERNS = {
    'chrome': ['chrome', 'google-chrome', 'chromium'],
    'firefox': ['firefox', 'firefox-esr'],
    'brave': ['brave', 'brave-browser'],
    'edge': ['microsoft-edge', 'msedge'],
    'opera': ['opera'],
    'vivaldi': ['vivaldi']
}


def setup_argparse():
    """Setup command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog='memory_monitor.py',
        description='OOM Tracker - Proactive memory monitor that prevents system crashes '
                    'by killing browser processes when memory usage is high.',
        epilog='For more information, see README.md or check the logs in ~/Utils/oom-tracker/logs/',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {VERSION}'
    )

    parser.add_argument(
        '--config',
        metavar='PATH',
        type=str,
        default=str(CONFIG_FILE),
        help=f'Path to configuration file (default: {CONFIG_FILE})'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test mode - log actions without actually killing processes (overrides config)'
    )

    parser.add_argument(
        '--threshold',
        metavar='N',
        type=int,
        help='Memory threshold percentage 0-100 (overrides config)'
    )

    parser.add_argument(
        '--swap-threshold',
        metavar='N',
        type=int,
        help='Swap threshold percentage 0-100 (overrides config)'
    )

    parser.add_argument(
        '--check',
        action='store_true',
        help='Check memory status and show top consumers, then exit without taking action'
    )

    parser.add_argument(
        '--list-browsers',
        action='store_true',
        help='List all running browser instances and their memory usage, then exit'
    )

    parser.add_argument(
        '--list-tabs',
        action='store_true',
        help='List all browser tabs (renderer processes) with memory usage, then exit'
    )

    parser.add_argument(
        '--analyze-dmesg',
        metavar='PATH',
        type=str,
        help='Analyze gzipped or plain text dmesg log file for OOM events and likely causes'
    )

    parser.add_argument(
        '--analyze-oom',
        metavar='DAYS',
        type=int,
        nargs='?',
        const=7,
        help='Analyze journalctl logs for OOM events from past N days (default: 7)'
    )

    parser.add_argument(
        '--snapshot',
        action='store_true',
        help='Start continuous memory snapshot logging (run as daemon to track OOM causes)'
    )

    parser.add_argument(
        '--snapshot-interval',
        metavar='SECS',
        type=int,
        default=30,
        help='Interval between snapshots in seconds (default: 30)'
    )

    parser.add_argument(
        '--analyze-snapshots',
        metavar='MINUTES',
        type=int,
        nargs='?',
        const=60,
        help='Analyze memory snapshots from past N minutes to find memory hogs (default: 60)'
    )

    parser.add_argument(
        '--correlate-oom',
        action='store_true',
        help='Correlate recent OOM events with memory snapshots to identify true culprits'
    )

    parser.add_argument(
        '--protect-session',
        action='store_true',
        help='Configure OOM score adjustments to protect critical session processes'
    )

    parser.add_argument(
        '--show-oom-scores',
        action='store_true',
        help='Show OOM scores for all running processes'
    )

    # Service management options
    service_group = parser.add_argument_group('service management')
    service_group.add_argument(
        '--enable-service',
        action='store_true',
        help='Enable and start the systemd timer for automated monitoring'
    )

    service_group.add_argument(
        '--disable-service',
        action='store_true',
        help='Disable and stop the systemd timer'
    )

    service_group.add_argument(
        '--service-status',
        action='store_true',
        help='Show systemd service and timer status'
    )

    service_group.add_argument(
        '--logs',
        action='store_true',
        help='View recent logs from the service'
    )

    service_group.add_argument(
        '--follow-logs',
        action='store_true',
        help='Follow logs in real-time (use with --logs or alone)'
    )

    service_group.add_argument(
        '--enable-snapshot-daemon',
        action='store_true',
        help='Enable continuous memory snapshot logging as a systemd user service'
    )

    service_group.add_argument(
        '--disable-snapshot-daemon',
        action='store_true',
        help='Disable the memory snapshot logging service'
    )

    service_group.add_argument(
        '--snapshot-status',
        action='store_true',
        help='Show status of the memory snapshot daemon'
    )

    args = parser.parse_args()

    # Validate threshold if provided
    if args.threshold is not None:
        if args.threshold < 0 or args.threshold > 100:
            parser.error('--threshold must be between 0 and 100')

    # Validate swap threshold if provided
    if args.swap_threshold is not None:
        if args.swap_threshold < 0 or args.swap_threshold > 100:
            parser.error('--swap-threshold must be between 0 and 100')

    return args


def load_config(config_path=None):
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = CONFIG_FILE

    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"Error loading config from {config_path}: {e}", file=sys.stderr)
        return {
            'memory_threshold_percent': 90,
            'kill_timeout_seconds': 30,
            'log_level': 'INFO',
            'log_max_bytes': 10485760,
            'log_backup_count': 5,
            'dry_run': False
        }


def setup_logging(config):
    """Setup logging with rotation."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger('oom-tracker')
    logger.setLevel(getattr(logging, config.get('log_level', 'INFO')))

    # File handler with rotation
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=config.get('log_max_bytes', 10485760),
        backupCount=config.get('log_backup_count', 5)
    )
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # JSON formatter for structured logging
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_memory_usage():
    """Get current memory usage percentage."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    # Calculate based on available memory
    # This accounts for buffers/cache that can be reclaimed
    usage_percent = 100.0 - (mem.available / mem.total * 100.0)
    return {
        'total_gb': mem.total / (1024**3),
        'available_gb': mem.available / (1024**3),
        'used_gb': mem.used / (1024**3),
        'percent': usage_percent,
        'swap_total_gb': swap.total / (1024**3),
        'swap_used_gb': swap.used / (1024**3),
        'swap_percent': swap.percent
    }


def get_process_swap(pid):
    """Get swap usage for a process from /proc/[pid]/status."""
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('VmSwap:'):
                    # Format: "VmSwap:    1234 kB"
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1]) / 1024  # Convert kB to MB
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return 0.0


def get_process_details(pid):
    """Get detailed process info similar to 'ps p <pid>' output."""
    try:
        proc = psutil.Process(pid)

        # Get process info
        with proc.oneshot():
            create_time = datetime.fromtimestamp(proc.create_time())
            elapsed = datetime.now() - create_time

            # Format elapsed time like ps (days-HH:MM:SS or HH:MM:SS)
            total_seconds = int(elapsed.total_seconds())
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            minutes = (total_seconds % 3600) // 60
            seconds = total_seconds % 60

            if days > 0:
                elapsed_str = f"{days}-{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

            # Get CPU and memory percent
            cpu_percent = proc.cpu_percent(interval=0.1)
            mem_percent = proc.memory_percent()

            # Get status
            status = proc.status()

            # Get command line (truncate if too long)
            try:
                cmdline = proc.cmdline()
                cmd_str = ' '.join(cmdline) if cmdline else proc.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmd_str = proc.name()

            return {
                'pid': pid,
                'user': proc.username(),
                'cpu_percent': cpu_percent,
                'mem_percent': mem_percent,
                'status': status,
                'elapsed': elapsed_str,
                'start_time': create_time.strftime('%Y-%m-%d %H:%M'),
                'command': cmd_str
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        return None


def get_top_memory_consumers(limit=10, sort_by='memory'):
    """Get top N memory-consuming processes with swap usage.

    Args:
        limit: Number of processes to return
        sort_by: 'memory', 'swap', or 'total' (memory + swap)
    """
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info']):
        try:
            info = proc.info
            memory_mb = info['memory_info'].rss / (1024**2)
            swap_mb = get_process_swap(info['pid'])

            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'username': info['username'],
                'memory_mb': memory_mb,
                'swap_mb': swap_mb,
                'total_mb': memory_mb + swap_mb
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by specified field
    sort_key = {
        'memory': lambda x: x['memory_mb'],
        'swap': lambda x: x['swap_mb'],
        'total': lambda x: x['total_mb']
    }.get(sort_by, lambda x: x['memory_mb'])

    processes.sort(key=sort_key, reverse=True)
    return processes[:limit]


def identify_browser(proc_name, cmdline):
    """Identify if a process is a browser and which type."""
    proc_name_lower = proc_name.lower()
    cmdline_lower = ' '.join(cmdline).lower() if cmdline else ''

    for browser_family, patterns in BROWSER_PATTERNS.items():
        for pattern in patterns:
            if pattern in proc_name_lower or pattern in cmdline_lower:
                return browser_family
    return None


def find_browser_process_tree(current_username):
    """Find all browser process trees grouped by parent process."""
    browser_trees = {}

    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'ppid', 'status']):
        try:
            info = proc.info

            # Skip if not current user
            if info['username'] != current_username:
                continue

            # Skip zombie processes
            if info['status'] == psutil.STATUS_ZOMBIE:
                continue

            # Check if it's a browser
            browser_type = identify_browser(info['name'], info['cmdline'])
            if not browser_type:
                continue

            # Find the root parent process
            try:
                parent_pid = info['ppid']
                root_proc = proc

                # Walk up the tree to find the main browser process
                while parent_pid > 1:
                    try:
                        parent = psutil.Process(parent_pid)
                        parent_browser = identify_browser(parent.name(), parent.cmdline())
                        if parent_browser == browser_type:
                            root_proc = parent
                            parent_pid = parent.ppid()
                        else:
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        break

                root_pid = root_proc.pid

                # Create or update browser tree entry
                if root_pid not in browser_trees:
                    browser_trees[root_pid] = {
                        'browser_type': browser_type,
                        'root_process': root_proc,
                        'children': [],
                        'total_memory_mb': 0
                    }

                # Add process to tree
                memory_mb = proc.memory_info().rss / (1024**2)
                browser_trees[root_pid]['children'].append({
                    'pid': proc.pid,
                    'name': info['name'],
                    'memory_mb': memory_mb
                })
                browser_trees[root_pid]['total_memory_mb'] += memory_mb

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return browser_trees


def kill_browser_instance(browser_tree, timeout_seconds, dry_run=False):
    """Kill a browser instance (root process and all children)."""
    root_proc = browser_tree['root_process']
    browser_type = browser_tree['browser_type']
    total_memory_mb = browser_tree['total_memory_mb']

    result = {
        'browser_type': browser_type,
        'root_pid': root_proc.pid,
        'memory_freed_mb': total_memory_mb,
        'process_count': len(browser_tree['children']),
        'success': False,
        'method': None
    }

    if dry_run:
        result['success'] = True
        result['method'] = 'DRY_RUN'
        return result

    try:
        # Send SIGTERM for graceful shutdown
        root_proc.terminate()
        result['method'] = 'SIGTERM'

        # Wait for process to terminate
        try:
            root_proc.wait(timeout=timeout_seconds)
            result['success'] = True
        except psutil.TimeoutExpired:
            # Process didn't terminate, force kill
            try:
                root_proc.kill()
                result['method'] = 'SIGKILL'
                root_proc.wait(timeout=5)
                result['success'] = True
            except (psutil.NoSuchProcess, psutil.TimeoutExpired):
                result['success'] = False

    except psutil.NoSuchProcess:
        # Process already died
        result['success'] = True
        result['method'] = 'ALREADY_DEAD'
    except psutil.AccessDenied as e:
        result['success'] = False
        result['error'] = str(e)

    return result


def find_browser_tabs(browser_type, current_username):
    """Find all tab processes for a specific browser type."""
    tabs = []

    for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'memory_info']):
        try:
            info = proc.info

            # Skip if not current user
            if info['username'] != current_username:
                continue

            # Check if it's a browser process
            detected_browser = identify_browser(info['name'], info['cmdline'])
            if detected_browser != browser_type:
                continue

            # Check if it's a renderer process (tab)
            cmdline_str = ' '.join(info['cmdline']) if info['cmdline'] else ''
            if '--type=renderer' not in cmdline_str:
                continue

            # Get memory usage
            memory_mb = info['memory_info'].rss / (1024**2)

            tabs.append({
                'pid': info['pid'],
                'name': info['name'],
                'memory_mb': memory_mb,
                'process': proc
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by memory usage (highest first)
    tabs.sort(key=lambda x: x['memory_mb'], reverse=True)
    return tabs


def kill_browser_tab(tab, dry_run=False):
    """Kill a single browser tab (renderer process)."""
    result = {
        'pid': tab['pid'],
        'memory_freed_mb': tab['memory_mb'],
        'success': False,
        'method': None
    }

    if dry_run:
        result['success'] = True
        result['method'] = 'DRY_RUN'
        return result

    try:
        proc = tab['process']
        # Force kill tab immediately (SIGKILL)
        # Tabs don't need graceful shutdown - they'll show "Aw, Snap!"
        proc.kill()
        result['method'] = 'SIGKILL'

        # Wait briefly to ensure it's dead
        try:
            proc.wait(timeout=2)
            result['success'] = True
        except psutil.TimeoutExpired:
            result['success'] = False

    except psutil.NoSuchProcess:
        # Process already died
        result['success'] = True
        result['method'] = 'ALREADY_DEAD'
    except psutil.AccessDenied as e:
        result['success'] = False
        result['error'] = str(e)

    return result


def kill_tabs_strategy(browser_trees, config, logger, current_username):
    """
    Strategy B: Kill individual tabs before killing entire browser.
    Returns True if tabs were killed, False if we should kill the browser instead.
    """
    tab_threshold_mb = config.get('tab_memory_threshold_mb', 300)
    max_tabs = config.get('max_tabs_to_kill', 3)
    interval_seconds = config.get('tab_kill_interval_seconds', 5)
    dry_run = config.get('dry_run', False)

    tabs_killed = 0
    total_memory_freed = 0

    # Find the browser instance with the most memory
    if not browser_trees:
        return False

    target_pid, target_tree = max(browser_trees.items(),
                                   key=lambda x: x[1]['total_memory_mb'])
    browser_type = target_tree['browser_type']

    logger.info(f"Using tab-killing strategy for {browser_type.upper()} (PID {target_pid})")

    # Find all tabs for this browser
    tabs = find_browser_tabs(browser_type, current_username)

    if not tabs:
        logger.warning(f"No tabs found for {browser_type.upper()}")
        return False

    logger.info(f"Found {len(tabs)} tab(s) for {browser_type.upper()}")

    # Filter tabs by memory threshold
    eligible_tabs = [t for t in tabs if t['memory_mb'] >= tab_threshold_mb]

    if not eligible_tabs:
        logger.info(f"No tabs exceed threshold of {tab_threshold_mb} MB")
        return False

    logger.info(f"{len(eligible_tabs)} tab(s) exceed {tab_threshold_mb} MB threshold")

    # Kill up to max_tabs_to_kill tabs
    for i, tab in enumerate(eligible_tabs[:max_tabs]):
        logger.warning(f"Killing tab {i+1}/{max_tabs}: PID {tab['pid']} "
                      f"using {tab['memory_mb']:.1f} MB")

        result = kill_browser_tab(tab, dry_run=dry_run)

        if result['success']:
            tabs_killed += 1
            total_memory_freed += result['memory_freed_mb']
            logger.info(f"Successfully killed tab PID {result['pid']} "
                       f"using method: {result['method']}")
        else:
            logger.error(f"Failed to kill tab PID {result['pid']}")
            if 'error' in result:
                logger.error(f"Error: {result['error']}")

        # Wait between kills if not the last one
        if i < len(eligible_tabs[:max_tabs]) - 1:
            logger.info(f"Waiting {interval_seconds}s before killing next tab...")
            if not dry_run:
                time.sleep(interval_seconds)

    logger.info(f"Killed {tabs_killed} tab(s), freed approximately {total_memory_freed:.1f} MB")

    # Check if we killed any tabs
    if tabs_killed > 0:
        return True
    else:
        return False


def parse_oom_events(file_path):
    """Parse OOM events from dmesg log file (gzipped or plain text)."""
    oom_events = []
    current_event = None
    in_task_list = False
    task_list_processes = []

    # Regex patterns
    timestamp_re = re.compile(r'^\[\s*(\d+\.\d+)\]')
    oom_killer_re = re.compile(r'invoked oom-killer')
    trigger_process_re = re.compile(r'CPU:\s+\d+\s+PID:\s+(\d+)\s+Comm:\s+(\S+)')
    killed_process_re = re.compile(r'Out of memory: Killed process (\d+) \(([^)]+)\).*?total-vm:(\d+)kB.*?rss:(\d+)kB')
    mem_info_re = re.compile(r'(active_anon|inactive_anon|active_file|inactive_file):(\d+)kB')
    task_header_re = re.compile(r'\[\s*pid\s*\].*?name')
    task_entry_re = re.compile(r'\[\s*(\d+)\]\s+\d+\s+\d+\s+(\d+)\s+(\d+).*?\s+\d+\s+(\S+)\s*$')

    try:
        # Try to open as gzip first, fall back to plain text
        try:
            f = gzip.open(file_path, 'rt', encoding='utf-8', errors='replace')
            # Test if it's actually gzipped
            f.read(1)
            f.seek(0)
        except (gzip.BadGzipFile, OSError):
            f = open(file_path, 'r', encoding='utf-8', errors='replace')

        for line in f:
            line = line.rstrip()

            # Extract timestamp
            ts_match = timestamp_re.match(line)
            timestamp = ts_match.group(1) if ts_match else None

            # Start of new OOM event
            if oom_killer_re.search(line):
                # Save previous event if exists
                if current_event and current_event.get('killed_process'):
                    current_event['top_consumers'] = sorted(
                        task_list_processes,
                        key=lambda x: x['rss_kb'],
                        reverse=True
                    )[:10]
                    oom_events.append(current_event)

                # Start new event
                current_event = {
                    'timestamp': f'[{timestamp}]' if timestamp else 'unknown',
                    'trigger_process': None,
                    'trigger_pid': None,
                    'killed_process': None,
                    'killed_pid': None,
                    'total_vm_kb': 0,
                    'rss_kb': 0,
                    'memory_stats': {},
                    'top_consumers': []
                }
                in_task_list = False
                task_list_processes = []

            if not current_event:
                continue

            # Trigger process info
            trigger_match = trigger_process_re.search(line)
            if trigger_match and not current_event.get('trigger_pid'):
                current_event['trigger_pid'] = int(trigger_match.group(1))
                current_event['trigger_process'] = trigger_match.group(2)

            # Killed process info
            killed_match = killed_process_re.search(line)
            if killed_match:
                current_event['killed_pid'] = int(killed_match.group(1))
                current_event['killed_process'] = killed_match.group(2)
                current_event['total_vm_kb'] = int(killed_match.group(3))
                current_event['rss_kb'] = int(killed_match.group(4))

            # Memory stats
            for mem_match in mem_info_re.finditer(line):
                stat_name = mem_match.group(1)
                stat_value = int(mem_match.group(2))
                current_event['memory_stats'][stat_name] = stat_value

            # Task list header
            if task_header_re.search(line):
                in_task_list = True
                continue

            # Task list entries
            if in_task_list:
                task_match = task_entry_re.search(line)
                if task_match:
                    task_list_processes.append({
                        'pid': int(task_match.group(1)),
                        'total_vm_kb': int(task_match.group(2)),
                        'rss_kb': int(task_match.group(3)),
                        'name': task_match.group(4)
                    })
                elif line.strip() and not timestamp_re.match(line):
                    # End of task list
                    in_task_list = False

        # Save last event
        if current_event and current_event.get('killed_process'):
            current_event['top_consumers'] = sorted(
                task_list_processes,
                key=lambda x: x['rss_kb'],
                reverse=True
            )[:10]
            oom_events.append(current_event)

        f.close()
        return oom_events

    except FileNotFoundError:
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading {file_path}", file=sys.stderr)
        print("Try running with sudo:", file=sys.stderr)
        print(f"  sudo python3 {sys.argv[0]} --analyze-dmesg {file_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)
        sys.exit(1)


def analyze_dmesg_mode(file_path):
    """Analyze dmesg log for OOM events and display results."""
    print("="*60)
    print(f"DMESG OOM ANALYSIS: {file_path}")
    print("="*60)

    oom_events = parse_oom_events(file_path)

    if not oom_events:
        print("\nNo OOM events found in this log file.")
        print("="*60)
        return

    print(f"\nFound {len(oom_events)} OOM event(s)\n")

    # Display each OOM event
    for idx, event in enumerate(oom_events, 1):
        print(f"--- OOM Event #{idx} ---")
        print(f"Timestamp:       {event['timestamp']}")

        if event['trigger_process']:
            print(f"Triggered by:    {event['trigger_process']} (PID {event['trigger_pid']})")

        print(f"Killed process:  {event['killed_process']} (PID {event['killed_pid']})")
        print(f"Memory freed:    {event['rss_kb'] / 1024:.1f} MB (RSS)")

        if event['top_consumers']:
            print(f"\nTop {min(5, len(event['top_consumers']))} Memory Consumers at time of OOM:")
            for i, proc in enumerate(event['top_consumers'][:5], 1):
                print(f"  {i}. {proc['name']:<20} (PID {proc['pid']:<6}) - {proc['rss_kb'] / 1024:>8.1f} MB")

        if event['memory_stats']:
            print(f"\nMemory Stats:")
            for stat, value_kb in sorted(event['memory_stats'].items()):
                print(f"  {stat.replace('_', ' ').title():<20}: {value_kb / 1024:>8.1f} MB")

        print()

    # Summary and root cause analysis
    if len(oom_events) > 0:
        print("="*60)
        print("SUMMARY & ROOT CAUSE ANALYSIS")
        print("="*60)

        # Count killed processes
        killed_counts = defaultdict(int)
        for event in oom_events:
            killed_counts[event['killed_process']] += 1

        print("\nProcesses killed by OOM:")
        for proc_name, count in sorted(killed_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {proc_name}: {count} time(s)")

        # Find consistent memory consumers across events
        all_consumers = defaultdict(list)
        for event in oom_events:
            for consumer in event['top_consumers']:
                all_consumers[consumer['name']].append(consumer['rss_kb'])

        print(f"\nLikely root cause (top memory consumers across all events):")
        consumer_stats = []
        for name, rss_list in all_consumers.items():
            consumer_stats.append({
                'name': name,
                'avg_mb': sum(rss_list) / len(rss_list) / 1024,
                'count': len(rss_list),
                'total_events': len(oom_events)
            })

        consumer_stats.sort(key=lambda x: x['avg_mb'], reverse=True)

        for i, stat in enumerate(consumer_stats[:5], 1):
            print(f"  {i}. {stat['name']:<20} - Average {stat['avg_mb']:>6.1f} MB "
                  f"(present in {stat['count']}/{stat['total_events']} events)")

        print(f"\nRecommendation: Consider limiting memory usage or adding more RAM/swap")
        print("="*60)


def enable_service():
    """Enable and start the systemd timer."""
    print("Enabling OOM Tracker service...")
    print()

    try:
        # Enable and start the timer
        result = subprocess.run(
            ['systemctl', '--user', 'enable', '--now', 'oom-tracker.timer'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✓ Service enabled and started successfully")
            print()

            # Show status
            subprocess.run(['systemctl', '--user', 'status', 'oom-tracker.timer', '--no-pager'])

            print()
            print("The OOM tracker will now run every 60 seconds.")
            print("View logs with: python3 memory_monitor.py --logs")
        else:
            print(f"✗ Failed to enable service: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    except FileNotFoundError:
        print("Error: systemctl not found. Is systemd installed?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def disable_service():
    """Disable and stop the systemd timer."""
    print("Disabling OOM Tracker service...")
    print()

    try:
        # Disable and stop the timer
        result = subprocess.run(
            ['systemctl', '--user', 'disable', '--now', 'oom-tracker.timer'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✓ Service disabled and stopped successfully")
            print()
            print("The OOM tracker will no longer run automatically.")
            print("You can re-enable it with: python3 memory_monitor.py --enable-service")
        else:
            print(f"✗ Failed to disable service: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    except FileNotFoundError:
        print("Error: systemctl not found. Is systemd installed?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def service_status():
    """Show the status of the systemd service and timer."""
    print("="*60)
    print("OOM TRACKER SERVICE STATUS")
    print("="*60)
    print()

    try:
        # Check timer status
        print("Timer Status:")
        print("-" * 60)
        subprocess.run(['systemctl', '--user', 'status', 'oom-tracker.timer', '--no-pager'])

        print()
        print("Upcoming Runs:")
        print("-" * 60)
        subprocess.run(['systemctl', '--user', 'list-timers', 'oom-tracker.timer', '--no-pager'])

        print()
        print("Recent Service Runs:")
        print("-" * 60)
        subprocess.run(['systemctl', '--user', 'status', 'oom-tracker.service', '--no-pager', '-n', '0'])

    except FileNotFoundError:
        print("Error: systemctl not found. Is systemd installed?", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def enable_snapshot_daemon():
    """Enable the memory snapshot daemon as a systemd user service."""
    print("Enabling OOM Tracker Snapshot Daemon...")
    print()

    service_file = SCRIPT_DIR / 'oom-tracker-snapshot.service'
    user_service_dir = Path.home() / '.config' / 'systemd' / 'user'

    try:
        # Create user systemd directory if it doesn't exist
        user_service_dir.mkdir(parents=True, exist_ok=True)

        # Copy service file
        dest_file = user_service_dir / 'oom-tracker-snapshot.service'

        # Read and update the service file with correct path
        with open(service_file, 'r') as f:
            service_content = f.read()

        # Replace the path placeholder with actual path
        service_content = service_content.replace(
            '%h/work/Utils/oom-tracker/memory_monitor.py',
            str(SCRIPT_DIR / 'memory_monitor.py')
        )

        with open(dest_file, 'w') as f:
            f.write(service_content)

        print(f"Installed service file to: {dest_file}")

        # Reload systemd
        subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)

        # Enable and start the service
        result = subprocess.run(
            ['systemctl', '--user', 'enable', '--now', 'oom-tracker-snapshot.service'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✓ Snapshot daemon enabled and started")
            print()
            print("Memory snapshots are now being logged continuously.")
            print(f"Snapshots saved to: {SNAPSHOT_FILE}")
            print()
            print("Useful commands:")
            print("  Check status:     python3 memory_monitor.py --snapshot-status")
            print("  Analyze:          python3 memory_monitor.py --analyze-snapshots")
            print("  Correlate OOM:    python3 memory_monitor.py --correlate-oom")
            print("  View logs:        journalctl --user -u oom-tracker-snapshot -f")
        else:
            print(f"✗ Failed to enable service: {result.stderr}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def disable_snapshot_daemon():
    """Disable the memory snapshot daemon."""
    print("Disabling OOM Tracker Snapshot Daemon...")

    try:
        result = subprocess.run(
            ['systemctl', '--user', 'disable', '--now', 'oom-tracker-snapshot.service'],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("✓ Snapshot daemon disabled and stopped")
        else:
            print(f"Note: {result.stderr.strip()}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def snapshot_daemon_status():
    """Show status of the memory snapshot daemon."""
    print("="*60)
    print("OOM TRACKER SNAPSHOT DAEMON STATUS")
    print("="*60)
    print()

    try:
        # Check service status
        subprocess.run(
            ['systemctl', '--user', 'status', 'oom-tracker-snapshot.service', '--no-pager'],
            check=False
        )

        # Show snapshot file info
        print()
        print("-"*60)
        if SNAPSHOT_FILE.exists():
            size_mb = SNAPSHOT_FILE.stat().st_size / (1024**2)
            # Count lines (snapshots)
            with open(SNAPSHOT_FILE, 'r') as f:
                snapshot_count = sum(1 for _ in f)
            print(f"Snapshot file: {SNAPSHOT_FILE}")
            print(f"  Size: {size_mb:.2f} MB")
            print(f"  Snapshots: {snapshot_count}")

            # Show most recent snapshot
            with open(SNAPSHOT_FILE, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_snap = json.loads(lines[-1])
                    print(f"  Last snapshot: {last_snap['timestamp']}")
        else:
            print(f"Snapshot file not found: {SNAPSHOT_FILE}")
            print("Snapshot daemon may not be running.")

    except FileNotFoundError:
        print("Error: systemctl not found", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

    print("="*60)


def show_logs(follow=False):
    """Show logs from the systemd service."""
    try:
        if follow:
            print("Following OOM Tracker logs (Ctrl+C to exit)...")
            print()
            subprocess.run(['journalctl', '--user', '-u', 'oom-tracker.service', '-f'])
        else:
            print("="*60)
            print("OOM TRACKER RECENT LOGS")
            print("="*60)
            print()
            subprocess.run(['journalctl', '--user', '-u', 'oom-tracker.service', '--no-pager', '-n', '50'])
            print()
            print("Tip: Use --follow-logs to watch logs in real-time")

    except FileNotFoundError:
        print("Error: journalctl not found. Is systemd installed?", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nStopped following logs")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def check_memory_mode():
    """Check memory status and display information without taking action."""
    print("="*70)
    print("MEMORY STATUS CHECK")
    print("="*70)

    # Get memory usage
    mem_usage = get_memory_usage()
    print(f"\nMemory Usage: {mem_usage['percent']:.1f}%")
    print(f"  Total:     {mem_usage['total_gb']:.2f} GB")
    print(f"  Used:      {mem_usage['used_gb']:.2f} GB")
    print(f"  Available: {mem_usage['available_gb']:.2f} GB")

    print(f"\nSwap Usage: {mem_usage['swap_percent']:.1f}%")
    print(f"  Total:     {mem_usage['swap_total_gb']:.2f} GB")
    print(f"  Used:      {mem_usage['swap_used_gb']:.2f} GB")

    # Load config for thresholds
    config = load_config()
    mem_threshold = config.get('memory_threshold_percent', 90)
    swap_threshold = config.get('swap_threshold_percent', 50)

    # Get top consumers (increased to 10 by default)
    top_consumers = get_top_memory_consumers(10, sort_by='total')

    # Show top memory consumers
    print(f"\nTop 10 Memory Consumers (by RAM):")
    print(f"  {'#':<3} {'PID':<8} {'Process':<20} {'User':<12} {'RAM':>10} {'Swap':>10} {'Total':>10}")
    print(f"  {'-'*3} {'-'*8} {'-'*20} {'-'*12} {'-'*10} {'-'*10} {'-'*10}")

    # Sort by memory for this display
    by_memory = sorted(top_consumers, key=lambda x: x['memory_mb'], reverse=True)
    for i, proc in enumerate(by_memory, 1):
        print(f"  {i:<3} {proc['pid']:<8} {proc['name']:<20} {proc['username']:<12} "
              f"{proc['memory_mb']:>9.1f}M {proc['swap_mb']:>9.1f}M {proc['total_mb']:>9.1f}M")

    # Show top swap consumers if there's significant swap usage
    swap_consumers = [p for p in top_consumers if p['swap_mb'] > 1]
    if swap_consumers:
        print(f"\nTop Swap Consumers:")
        print(f"  {'#':<3} {'PID':<8} {'Process':<20} {'User':<12} {'Swap':>10} {'RAM':>10}")
        print(f"  {'-'*3} {'-'*8} {'-'*20} {'-'*12} {'-'*10} {'-'*10}")

        by_swap = sorted(swap_consumers, key=lambda x: x['swap_mb'], reverse=True)[:10]
        for i, proc in enumerate(by_swap, 1):
            print(f"  {i:<3} {proc['pid']:<8} {proc['name']:<20} {proc['username']:<12} "
                  f"{proc['swap_mb']:>9.1f}M {proc['memory_mb']:>9.1f}M")

        # Show detailed process info for top 5 swap consumers
        print(f"\nTop Swap Consumers - Process Details (ps-style):")
        print(f"  {'PID':<8} {'USER':<12} {'%CPU':>6} {'%MEM':>6} {'RSS':>10} {'SWAP':>10} {'STAT':<8} {'ELAPSED':>15} {'STARTED':<16}")
        print(f"  {'-'*8} {'-'*12} {'-'*6} {'-'*6} {'-'*10} {'-'*10} {'-'*8} {'-'*15} {'-'*16}")

        for proc in by_swap[:5]:
            details = get_process_details(proc['pid'])
            if details:
                print(f"  {details['pid']:<8} {details['user']:<12} {details['cpu_percent']:>5.1f}% "
                      f"{details['mem_percent']:>5.1f}% {proc['memory_mb']:>9.1f}M {proc['swap_mb']:>9.1f}M "
                      f"{details['status']:<8} {details['elapsed']:>15} {details['start_time']:<16}")

        # Show command lines for top 5 swap consumers
        print(f"\n  Command lines:")
        for proc in by_swap[:5]:
            details = get_process_details(proc['pid'])
            if details:
                cmd = details['command']
                # Truncate long commands
                if len(cmd) > 100:
                    cmd = cmd[:97] + "..."
                print(f"  [{proc['pid']}] {cmd}")
    else:
        print(f"\nNo significant swap usage detected.")

    # Always show process details for top memory consumers
    print(f"\nTop Memory Consumers - Process Details (ps-style):")
    print(f"  {'PID':<8} {'USER':<12} {'%CPU':>6} {'%MEM':>6} {'RSS':>10} {'SWAP':>10} {'STAT':<8} {'ELAPSED':>15} {'STARTED':<16}")
    print(f"  {'-'*8} {'-'*12} {'-'*6} {'-'*6} {'-'*10} {'-'*10} {'-'*8} {'-'*15} {'-'*16}")

    for proc in by_memory[:5]:
        details = get_process_details(proc['pid'])
        if details:
            print(f"  {details['pid']:<8} {details['user']:<12} {details['cpu_percent']:>5.1f}% "
                  f"{details['mem_percent']:>5.1f}% {proc['memory_mb']:>9.1f}M {proc['swap_mb']:>9.1f}M "
                  f"{details['status']:<8} {details['elapsed']:>15} {details['start_time']:<16}")

    # Show command lines for top 5 memory consumers
    print(f"\n  Command lines:")
    for proc in by_memory[:5]:
        details = get_process_details(proc['pid'])
        if details:
            cmd = details['command']
            # Truncate long commands
            if len(cmd) > 100:
                cmd = cmd[:97] + "..."
            print(f"  [{proc['pid']}] {cmd}")

    # Check against thresholds
    print(f"\n{'='*70}")
    print("THRESHOLD STATUS")
    print(f"{'='*70}")
    print(f"\nConfigured Thresholds:")
    print(f"  Memory: {mem_threshold}%")
    print(f"  Swap:   {swap_threshold}%")

    mem_exceeded = mem_usage['percent'] >= mem_threshold
    swap_exceeded = mem_usage['swap_percent'] >= swap_threshold

    print(f"\nCurrent Status:")
    if mem_exceeded:
        print(f"  ⚠  MEMORY EXCEEDS threshold by {mem_usage['percent'] - mem_threshold:.1f}%")
    else:
        print(f"  ✓  Memory below threshold by {mem_threshold - mem_usage['percent']:.1f}%")

    if swap_exceeded:
        print(f"  ⚠  SWAP EXCEEDS threshold by {mem_usage['swap_percent'] - swap_threshold:.1f}%")
    else:
        print(f"  ✓  Swap below threshold by {swap_threshold - mem_usage['swap_percent']:.1f}%")

    if mem_exceeded or swap_exceeded:
        print(f"\n  → Monitor would TAKE ACTION if running normally")
    else:
        print(f"\n  → No action needed")

    print("="*70)


def list_browsers_mode():
    """List all browser instances and their memory usage."""
    print("="*60)
    print("BROWSER MEMORY USAGE")
    print("="*60)

    current_username = psutil.Process().username()
    browser_trees = find_browser_process_tree(current_username)

    if not browser_trees:
        print("\nNo browser processes found running under user:", current_username)
        print("="*60)
        return

    # Calculate totals by browser type
    totals_by_type = {}
    for root_pid, tree in browser_trees.items():
        browser_type = tree['browser_type']
        if browser_type not in totals_by_type:
            totals_by_type[browser_type] = {
                'memory_mb': 0,
                'instances': 0,
                'processes': 0
            }
        totals_by_type[browser_type]['memory_mb'] += tree['total_memory_mb']
        totals_by_type[browser_type]['instances'] += 1
        totals_by_type[browser_type]['processes'] += len(tree['children'])

    # Display summary
    print(f"\nSummary ({len(browser_trees)} browser instance(s) found):")
    for browser_type, stats in sorted(totals_by_type.items()):
        print(f"  {browser_type.upper()}: {stats['memory_mb']:.1f} MB "
              f"({stats['instances']} instance(s), {stats['processes']} process(es))")

    # Display individual instances
    print(f"\nDetailed Breakdown:")
    sorted_browsers = sorted(browser_trees.items(),
                            key=lambda x: x[1]['total_memory_mb'],
                            reverse=True)

    for root_pid, tree in sorted_browsers:
        print(f"\n  {tree['browser_type'].upper()} - PID {root_pid}")
        print(f"    Total Memory: {tree['total_memory_mb']:.1f} MB")
        print(f"    Processes:    {len(tree['children'])}")

        # Show top 5 processes in this browser tree
        top_children = sorted(tree['children'],
                            key=lambda x: x['memory_mb'],
                            reverse=True)[:5]
        if len(tree['children']) > 5:
            print(f"    Top 5 processes:")
        for child in top_children:
            print(f"      PID {child['pid']:>6}: {child['name']:<25} - {child['memory_mb']:>8.1f} MB")

    # Grand total
    total_browser_memory = sum(tree['total_memory_mb'] for tree in browser_trees.values())
    total_processes = sum(len(tree['children']) for tree in browser_trees.values())

    print(f"\nTotal Browser Memory: {total_browser_memory:.1f} MB across {total_processes} processes")
    print("="*60)


def list_tabs_mode():
    """List all browser tabs (renderer processes) with memory usage."""
    print("="*60)
    print("BROWSER TABS MEMORY USAGE")
    print("="*60)

    current_username = psutil.Process().username()

    # Find all browser types
    all_tabs = {}
    for browser_type in ['chrome', 'firefox', 'brave', 'edge', 'opera', 'vivaldi']:
        tabs = find_browser_tabs(browser_type, current_username)
        if tabs:
            all_tabs[browser_type] = tabs

    if not all_tabs:
        print("\nNo browser tabs found running under user:", current_username)
        print("="*60)
        return

    total_tabs = sum(len(tabs) for tabs in all_tabs.values())
    total_memory = sum(sum(t['memory_mb'] for t in tabs) for tabs in all_tabs.values())

    print(f"\nFound {total_tabs} tab(s) across {len(all_tabs)} browser(s)")
    print(f"Total tab memory: {total_memory:.1f} MB\n")

    # Display tabs by browser
    for browser_type, tabs in sorted(all_tabs.items()):
        browser_memory = sum(t['memory_mb'] for t in tabs)
        print(f"\n{browser_type.upper()} - {len(tabs)} tab(s), {browser_memory:.1f} MB total")
        print("-"*60)

        # Show all tabs sorted by memory
        for i, tab in enumerate(tabs, 1):
            marker = "  "
            # Mark tabs that would be killed with current config
            config = load_config()
            threshold = config.get('tab_memory_threshold_mb', 300)
            if tab['memory_mb'] >= threshold:
                marker = "→ "  # This tab exceeds threshold

            print(f"{marker}{i:>2}. PID {tab['pid']:<8} - {tab['memory_mb']:>8.1f} MB")

    # Show configuration
    print(f"\n{'='*60}")
    print("CONFIGURATION")
    print(f"{'='*60}")
    config = load_config()
    kill_mode = config.get('kill_mode', 'browser')
    threshold = config.get('tab_memory_threshold_mb', 300)
    max_tabs = config.get('max_tabs_to_kill', 3)

    print(f"Kill mode:           {kill_mode}")
    print(f"Tab threshold:       {threshold} MB")
    print(f"Max tabs to kill:    {max_tabs}")

    # Show which tabs would be killed
    eligible_tabs = []
    for tabs in all_tabs.values():
        eligible_tabs.extend([t for t in tabs if t['memory_mb'] >= threshold])
    eligible_tabs.sort(key=lambda x: x['memory_mb'], reverse=True)

    if kill_mode == 'tab' and eligible_tabs:
        print(f"\nTabs that would be killed (marked with →):")
        print(f"  {len(eligible_tabs[:max_tabs])} tab(s) eligible for killing")
        print(f"  Would free: {sum(t['memory_mb'] for t in eligible_tabs[:max_tabs]):.1f} MB")
    elif kill_mode == 'tab':
        print(f"\nNo tabs exceed the {threshold} MB threshold")
    else:
        print(f"\nTab killing disabled (kill_mode={kill_mode})")

    print("="*60)


def get_recent_reboots(days=7):
    """Get recent system reboots from last command."""
    try:
        result = subprocess.run(
            ['last', 'reboot', '-s', f'-{days} days'],
            capture_output=True,
            text=True,
            timeout=10
        )

        reboots = []
        for line in result.stdout.splitlines():
            if 'system boot' in line.lower():
                # Parse the line to extract timestamp
                parts = line.split()
                if len(parts) >= 5:
                    # Format: "reboot system boot kernel Weekday Month Day HH:MM"
                    month = parts[4]
                    day = parts[5]
                    time = parts[6]
                    timestamp = f"{month} {day} {time}"
                    reboots.append(timestamp)

        return reboots
    except Exception:
        return []


def analyze_journalctl_oom(days=7):
    """Analyze journalctl logs for OOM events with detailed timeline."""
    print("="*70)
    print(f"SYSTEM OOM ANALYSIS - LAST {days} DAYS")
    print("="*70)

    # Get recent reboots
    reboots = get_recent_reboots(days)
    if reboots:
        print(f"\nSystem Reboots in this period: {len(reboots)}")
        for i, reboot in enumerate(reboots, 1):
            print(f"  {i}. {reboot}")
        print()

    try:
        # Query journalctl for OOM events with ISO timestamps for precision
        since_date = datetime.now().timestamp() - (days * 86400)
        result = subprocess.run(
            ['journalctl', '-k', '--since', f'{days} days ago', '--no-pager', '-o', 'short-iso'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"Error querying journalctl: {result.stderr}", file=sys.stderr)
            sys.exit(1)

        lines = result.stdout.splitlines()

    except subprocess.TimeoutExpired:
        print("Error: journalctl query timed out", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: journalctl not found", file=sys.stderr)
        sys.exit(1)

    # Parse OOM events
    oom_events = []
    current_event = None
    task_list_processes = []

    # Support both ISO and traditional timestamp formats
    timestamp_iso_re = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})')
    timestamp_re = re.compile(r'^(\w+\s+\d+\s+\d+:\d+:\d+)')
    oom_killer_re = re.compile(r'invoked oom-killer')
    trigger_process_re = re.compile(r'CPU:\s+\d+\s+PID:\s+(\d+)\s+Comm:\s+(\S+)')
    killed_process_re = re.compile(r'Out of memory: Killed process (\d+) \(([^)]+)\).*?total-vm:(\d+)kB.*?(?:anon-rss|rss):(\d+)kB')
    mem_info_re = re.compile(r'(active_anon|inactive_anon|active_file|inactive_file):(\d+)')
    task_entry_re = re.compile(r'\[\s*(\d+)\]\s+\d+\s+\d+\s+(\d+)\s+(\d+).*?\s+\d+\s+(\S+)\s*$')

    for line in lines:
        # Extract timestamp (prefer ISO format for precision)
        ts_match = timestamp_iso_re.match(line)
        if ts_match:
            timestamp = ts_match.group(1)
            try:
                timestamp_dt = datetime.fromisoformat(timestamp.replace('+', '+'))
                timestamp_epoch = timestamp_dt.timestamp()
            except ValueError:
                timestamp_epoch = None
        else:
            ts_match = timestamp_re.match(line)
            timestamp = ts_match.group(1) if ts_match else None
            timestamp_epoch = None

        # Start of new OOM event
        if oom_killer_re.search(line):
            if current_event and current_event.get('killed_process'):
                oom_events.append(current_event)

            current_event = {
                'timestamp': timestamp or 'unknown',
                'timestamp_epoch': timestamp_epoch,
                'trigger_process': None,
                'trigger_pid': None,
                'killed_process': None,
                'killed_pid': None,
                'total_vm_kb': 0,
                'rss_kb': 0,
                'memory_stats': {},
                'top_consumers': []
            }
            task_list_processes = []

        if not current_event:
            continue

        # Trigger process info
        trigger_match = trigger_process_re.search(line)
        if trigger_match and not current_event.get('trigger_pid'):
            current_event['trigger_pid'] = int(trigger_match.group(1))
            current_event['trigger_process'] = trigger_match.group(2)

        # Killed process info
        killed_match = killed_process_re.search(line)
        if killed_match:
            current_event['killed_pid'] = int(killed_match.group(1))
            current_event['killed_process'] = killed_match.group(2)
            current_event['total_vm_kb'] = int(killed_match.group(3))
            current_event['rss_kb'] = int(killed_match.group(4))

        # Memory stats
        for mem_match in mem_info_re.finditer(line):
            stat_name = mem_match.group(1)
            stat_value = int(mem_match.group(2))
            current_event['memory_stats'][stat_name] = stat_value

        # Task list entries
        task_match = task_entry_re.search(line)
        if task_match:
            task_list_processes.append({
                'pid': int(task_match.group(1)),
                'total_vm_kb': int(task_match.group(2)),
                'rss_kb': int(task_match.group(3)),
                'name': task_match.group(4)
            })

    # Save last event
    if current_event and current_event.get('killed_process'):
        current_event['top_consumers'] = sorted(
            task_list_processes,
            key=lambda x: x['rss_kb'],
            reverse=True
        )[:10]
        oom_events.append(current_event)

    if not oom_events:
        print(f"\n✓ No OOM events found in the last {days} days")
        print("\nYour system has been stable!")
        print("="*70)
        return

    print(f"\n⚠ Found {len(oom_events)} OOM event(s)\n")

    # Display timeline
    print("TIMELINE OF OOM EVENTS")
    print("-"*70)
    for idx, event in enumerate(oom_events, 1):
        print(f"\n{idx}. {event['timestamp']}")
        print(f"   Killed: {event['killed_process']} (PID {event['killed_pid']}) - "
              f"Freed {event['rss_kb'] / 1024:.1f} MB")
        if event['trigger_process']:
            print(f"   Triggered by: {event['trigger_process']} (PID {event['trigger_pid']})")

    # Detailed analysis of most recent event
    latest_event = oom_events[-1]
    print(f"\n\n{'='*70}")
    print("MOST RECENT OOM EVENT - DETAILED ANALYSIS")
    print(f"{'='*70}")
    print(f"\nTimestamp:       {latest_event['timestamp']}")

    if latest_event['trigger_process']:
        print(f"Triggered by:    {latest_event['trigger_process']} (PID {latest_event['trigger_pid']})")

    print(f"Killed process:  {latest_event['killed_process']} (PID {latest_event['killed_pid']})")
    print(f"Memory freed:    {latest_event['rss_kb'] / 1024:.1f} MB (RSS)")

    if latest_event['top_consumers']:
        print(f"\nTop {min(5, len(latest_event['top_consumers']))} Memory Consumers at Time of OOM:")
        for i, proc in enumerate(latest_event['top_consumers'][:5], 1):
            print(f"  {i}. {proc['name']:<20} (PID {proc['pid']:<6}) - {proc['rss_kb'] / 1024:>8.1f} MB")

    # Root cause analysis
    print(f"\n\n{'='*70}")
    print("ROOT CAUSE ANALYSIS")
    print(f"{'='*70}")

    # Count killed processes
    killed_counts = defaultdict(int)
    for event in oom_events:
        killed_counts[event['killed_process']] += 1

    print("\nProcesses Killed by OOM Killer:")
    for proc_name, count in sorted(killed_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  • {proc_name}: {count} time(s)")

    # Find consistent memory consumers
    all_consumers = defaultdict(list)
    for event in oom_events:
        for consumer in event['top_consumers']:
            all_consumers[consumer['name']].append(consumer['rss_kb'])

    if all_consumers:
        print(f"\nLikely Root Cause (Top Memory Consumers Across All Events):")
        consumer_stats = []
        for name, rss_list in all_consumers.items():
            consumer_stats.append({
                'name': name,
                'avg_mb': sum(rss_list) / len(rss_list) / 1024,
                'max_mb': max(rss_list) / 1024,
                'count': len(rss_list),
                'total_events': len(oom_events)
            })

        consumer_stats.sort(key=lambda x: x['avg_mb'], reverse=True)

        for i, stat in enumerate(consumer_stats[:5], 1):
            print(f"  {i}. {stat['name']:<20} - Avg: {stat['avg_mb']:>6.1f} MB, "
                  f"Max: {stat['max_mb']:>6.1f} MB "
                  f"(in {stat['count']}/{stat['total_events']} events)")

    # Recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDATIONS")
    print(f"{'='*70}")

    # Check if session processes were killed
    session_procs = ['gnome-shell', 'gnome-session', 'nautilus', 'systemd']
    session_killed = [p for p in killed_counts.keys() if any(sp in p.lower() for sp in session_procs)]

    if session_killed:
        print("\n⚠  CRITICAL: Session processes were killed, causing logout!")
        print(f"   Killed: {', '.join(session_killed)}")
        print("\n   To prevent future logouts:")
        print("   1. Run: python3 memory_monitor.py --protect-session")
        print("      This adjusts OOM scores to protect critical session processes")
        print("   2. Let the OOM tracker kill browsers proactively before kernel OOM")

    # Check browser memory
    browser_procs = ['chrome', 'firefox', 'brave', 'edge']
    if any(any(bp in name.lower() for bp in browser_procs) for name in all_consumers.keys()):
        print("\n   Browser memory consumption detected:")
        print("   • Enable OOM tracker service to kill browsers before system OOM")
        print("   • Consider closing browsers when not in use")
        print("   • Use browser extensions to suspend inactive tabs")

    # General recommendations
    total_mem_gb = psutil.virtual_memory().total / (1024**3)
    swap = psutil.swap_memory()
    swap_total_gb = swap.total / (1024**3)

    if total_mem_gb < 32:
        print(f"\n   Your system has {total_mem_gb:.0f}GB RAM. Consider:")
        print("   • Adding more physical RAM")
        if swap_total_gb < total_mem_gb * 0.5:
            print(f"   • Increasing swap space (current: {swap_total_gb:.1f}GB, recommended: {total_mem_gb * 0.5:.1f}GB+)")
        else:
            print(f"   • Increasing swap space (current: {swap_total_gb:.1f}GB)")

    print("\n   Immediate actions:")
    print("   • Enable OOM tracker: python3 memory_monitor.py --enable-service")
    print("   • Monitor memory: python3 memory_monitor.py --check")

    # Add note about correlation with reboots
    if len(oom_events) > 0 and reboots:
        print(f"\n   ⚠  Note: {len(oom_events)} OOM event(s) occurred, followed by {len(reboots)} reboot(s)")
        print("   This suggests OOM events may have caused system instability")

    # Check for snapshot data
    if SNAPSHOT_FILE.exists():
        print(f"\n   💡 Memory snapshots available! Run for detailed analysis:")
        print(f"      python3 memory_monitor.py --correlate-oom")
    else:
        print(f"\n   💡 To find the TRUE culprit behind OOM kills:")
        print(f"      1. Start snapshot daemon: python3 memory_monitor.py --snapshot &")
        print(f"      2. After next OOM, run: python3 memory_monitor.py --correlate-oom")

    print("="*70)


def show_oom_scores():
    """Show OOM scores for all running processes."""
    print("="*70)
    print("PROCESS OOM SCORES")
    print("="*70)
    print("\nOOM Score Guide:")
    print("  -1000 = Never kill (kernel processes)")
    print("   -900 = System critical (disable OOM killer)")
    print("   -100 = Protected from OOM")
    print("      0 = Normal priority (default)")
    print("    200 = Prefer to kill (desktop apps)")
    print("   1000 = Kill first")
    print()

    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            pid = proc.info['pid']
            oom_score_adj_file = f'/proc/{pid}/oom_score_adj'
            oom_score_file = f'/proc/{pid}/oom_score'

            try:
                with open(oom_score_adj_file, 'r') as f:
                    oom_score_adj = int(f.read().strip())
                with open(oom_score_file, 'r') as f:
                    oom_score = int(f.read().strip())

                processes.append({
                    'pid': pid,
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'oom_score_adj': oom_score_adj,
                    'oom_score': oom_score
                })
            except (FileNotFoundError, PermissionError):
                continue

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by oom_score (higher = more likely to be killed)
    processes.sort(key=lambda x: x['oom_score'], reverse=True)

    print(f"Top 20 processes most likely to be killed by OOM:")
    print(f"{'PID':<8} {'OOM Score':<10} {'Adj':<6} {'User':<12} {'Process':<30}")
    print("-"*70)

    for proc in processes[:20]:
        print(f"{proc['pid']:<8} {proc['oom_score']:<10} {proc['oom_score_adj']:<6} "
              f"{proc['username']:<12} {proc['name']:<30}")

    # Show protected processes
    protected = [p for p in processes if p['oom_score_adj'] < 0]
    if protected:
        print(f"\n\nProtected processes (OOM score < 0):")
        print(f"{'PID':<8} {'OOM Score':<10} {'Adj':<6} {'User':<12} {'Process':<30}")
        print("-"*70)
        for proc in sorted(protected, key=lambda x: x['oom_score_adj']):
            print(f"{proc['pid']:<8} {proc['oom_score']:<10} {proc['oom_score_adj']:<6} "
                  f"{proc['username']:<12} {proc['name']:<30}")

    print("="*70)


def snapshot_memory_state():
    """Capture a complete memory snapshot of all processes."""
    timestamp = datetime.now()

    # Get system memory
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    # Get all processes with memory info
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'create_time']):
        try:
            info = proc.info
            memory_mb = info['memory_info'].rss / (1024**2)
            swap_mb = get_process_swap(info['pid'])

            # Get oom_score
            try:
                with open(f'/proc/{info["pid"]}/oom_score', 'r') as f:
                    oom_score = int(f.read().strip())
            except (FileNotFoundError, PermissionError):
                oom_score = -1

            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'username': info['username'],
                'memory_mb': round(memory_mb, 1),
                'swap_mb': round(swap_mb, 1),
                'oom_score': oom_score,
                'age_hours': round((timestamp.timestamp() - info['create_time']) / 3600, 2) if info['create_time'] else 0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by memory (descending)
    processes.sort(key=lambda x: x['memory_mb'], reverse=True)

    snapshot = {
        'timestamp': timestamp.isoformat(),
        'timestamp_epoch': timestamp.timestamp(),
        'system': {
            'mem_percent': round(100 - (mem.available / mem.total * 100), 1),
            'mem_available_gb': round(mem.available / (1024**3), 2),
            'mem_total_gb': round(mem.total / (1024**3), 2),
            'swap_percent': round(swap.percent, 1),
            'swap_used_gb': round(swap.used / (1024**3), 2),
            'swap_total_gb': round(swap.total / (1024**3), 2)
        },
        'top_processes': processes[:20]  # Keep top 20 memory consumers
    }

    return snapshot


def run_snapshot_daemon(interval_seconds=30):
    """Run continuous memory snapshot logging."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print(f"OOM Tracker Memory Snapshot Daemon v{VERSION}")
    print(f"Logging to: {SNAPSHOT_FILE}")
    print(f"Interval: {interval_seconds} seconds")
    print("Press Ctrl+C to stop")
    print()

    def signal_handler(sig, frame):
        print("\n\nSnapshot daemon stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    snapshot_count = 0

    while True:
        try:
            snapshot = snapshot_memory_state()

            # Write to JSONL file
            with open(SNAPSHOT_FILE, 'a') as f:
                f.write(json.dumps(snapshot) + '\n')

            snapshot_count += 1

            # Print status
            sys_info = snapshot['system']
            top_proc = snapshot['top_processes'][0] if snapshot['top_processes'] else None

            status_line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
            status_line += f"Mem: {sys_info['mem_percent']:.1f}% | "
            status_line += f"Swap: {sys_info['swap_percent']:.1f}%"
            if top_proc:
                status_line += f" | Top: {top_proc['name'][:15]} ({top_proc['memory_mb']:.0f}MB)"
            print(status_line)

        except Exception as e:
            print(f"Error capturing snapshot: {e}", file=sys.stderr)

        time.sleep(interval_seconds)


def analyze_snapshots_mode(minutes=60):
    """Analyze recent memory snapshots to find memory hogs."""
    print("="*70)
    print(f"MEMORY SNAPSHOT ANALYSIS - LAST {minutes} MINUTES")
    print("="*70)

    if not SNAPSHOT_FILE.exists():
        print(f"\nNo snapshot file found at: {SNAPSHOT_FILE}")
        print("Run snapshot daemon first: python3 memory_monitor.py --snapshot")
        return

    cutoff_time = datetime.now().timestamp() - (minutes * 60)
    snapshots = []

    with open(SNAPSHOT_FILE, 'r') as f:
        for line in f:
            try:
                snap = json.loads(line)
                if snap.get('timestamp_epoch', 0) >= cutoff_time:
                    snapshots.append(snap)
            except json.JSONDecodeError:
                continue

    if not snapshots:
        print(f"\nNo snapshots found in the last {minutes} minutes.")
        print("Make sure the snapshot daemon is running.")
        return

    print(f"\nAnalyzed {len(snapshots)} snapshot(s)")
    print(f"Time range: {snapshots[0]['timestamp']} to {snapshots[-1]['timestamp']}")

    # Analyze memory pressure periods
    high_pressure_snaps = [s for s in snapshots if s['system']['mem_percent'] >= 85]

    if high_pressure_snaps:
        print(f"\n⚠  Found {len(high_pressure_snaps)} high memory pressure periods (>=85%)")

    # Track process memory over time
    process_stats = {}
    for snap in snapshots:
        for proc in snap['top_processes']:
            name = proc['name']
            if name not in process_stats:
                process_stats[name] = {
                    'samples': [],
                    'memory_mb': [],
                    'swap_mb': [],
                    'pids': set(),
                    'max_oom_score': 0
                }
            process_stats[name]['samples'].append(snap['timestamp'])
            process_stats[name]['memory_mb'].append(proc['memory_mb'])
            process_stats[name]['swap_mb'].append(proc['swap_mb'])
            process_stats[name]['pids'].add(proc['pid'])
            process_stats[name]['max_oom_score'] = max(process_stats[name]['max_oom_score'], proc.get('oom_score', 0))

    # Calculate stats for each process
    proc_summary = []
    for name, stats in process_stats.items():
        if len(stats['memory_mb']) > 0:
            proc_summary.append({
                'name': name,
                'avg_mb': sum(stats['memory_mb']) / len(stats['memory_mb']),
                'max_mb': max(stats['memory_mb']),
                'min_mb': min(stats['memory_mb']),
                'avg_swap_mb': sum(stats['swap_mb']) / len(stats['swap_mb']),
                'max_swap_mb': max(stats['swap_mb']),
                'samples': len(stats['memory_mb']),
                'total_samples': len(snapshots),
                'pids': len(stats['pids']),
                'max_oom_score': stats['max_oom_score'],
                'growth_mb': stats['memory_mb'][-1] - stats['memory_mb'][0] if len(stats['memory_mb']) > 1 else 0
            })

    # Sort by average memory usage
    proc_summary.sort(key=lambda x: x['avg_mb'], reverse=True)

    print(f"\n{'='*70}")
    print("TOP MEMORY CONSUMERS (by average)")
    print(f"{'='*70}")
    print(f"{'#':<3} {'Process':<20} {'Avg MB':>10} {'Max MB':>10} {'Swap MB':>10} {'OOM Score':>10} {'Growth':>10}")
    print(f"{'-'*3} {'-'*20} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for i, p in enumerate(proc_summary[:15], 1):
        growth_str = f"{p['growth_mb']:+.0f}" if p['growth_mb'] != 0 else "0"
        print(f"{i:<3} {p['name']:<20} {p['avg_mb']:>10.1f} {p['max_mb']:>10.1f} "
              f"{p['avg_swap_mb']:>10.1f} {p['max_oom_score']:>10} {growth_str:>10}")

    # Find processes with memory growth (potential leaks)
    growing_procs = [p for p in proc_summary if p['growth_mb'] > 100]
    if growing_procs:
        print(f"\n{'='*70}")
        print("⚠  PROCESSES WITH SIGNIFICANT MEMORY GROWTH (>100MB)")
        print(f"{'='*70}")
        for p in sorted(growing_procs, key=lambda x: x['growth_mb'], reverse=True):
            print(f"  {p['name']:<25} grew by {p['growth_mb']:+.0f} MB "
                  f"({p['min_mb']:.0f} MB → {p['max_mb']:.0f} MB)")

    # Show system memory trend
    if len(snapshots) > 1:
        first_mem = snapshots[0]['system']['mem_percent']
        last_mem = snapshots[-1]['system']['mem_percent']
        peak_mem = max(s['system']['mem_percent'] for s in snapshots)

        print(f"\n{'='*70}")
        print("SYSTEM MEMORY TREND")
        print(f"{'='*70}")
        print(f"  Start: {first_mem:.1f}%")
        print(f"  End:   {last_mem:.1f}%")
        print(f"  Peak:  {peak_mem:.1f}%")
        print(f"  Trend: {last_mem - first_mem:+.1f}%")

    # Identify likely OOM targets vs actual memory hogs
    print(f"\n{'='*70}")
    print("OOM KILLER PREDICTION")
    print(f"{'='*70}")
    print("\nProcesses most likely to be killed by OOM (high OOM score + big memory):")

    # Sort by combination of OOM score and memory
    oom_targets = sorted(proc_summary, key=lambda x: (x['max_oom_score'], x['avg_mb']), reverse=True)[:5]
    for i, p in enumerate(oom_targets, 1):
        print(f"  {i}. {p['name']:<20} OOM Score: {p['max_oom_score']:>4}, Avg: {p['avg_mb']:.0f} MB")

    print("\nActual biggest memory consumers (what SHOULD be killed):")
    for i, p in enumerate(proc_summary[:5], 1):
        print(f"  {i}. {p['name']:<20} Avg: {p['avg_mb']:.0f} MB, OOM Score: {p['max_oom_score']}")

    print("="*70)


def correlate_oom_with_snapshots():
    """Correlate OOM events with memory snapshots to identify true culprits."""
    print("="*70)
    print("OOM EVENT CORRELATION WITH MEMORY SNAPSHOTS")
    print("="*70)

    # First, get recent OOM events from journalctl
    try:
        result = subprocess.run(
            ['journalctl', '-k', '--since', '7 days ago', '--no-pager', '-o', 'short-iso'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"Error querying journalctl: {result.stderr}", file=sys.stderr)
            return

        lines = result.stdout.splitlines()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return

    # Parse OOM events with precise timestamps
    oom_events = []
    timestamp_re = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})')
    killed_re = re.compile(r'Out of memory: Killed process (\d+) \(([^)]+)\)')

    for line in lines:
        killed_match = killed_re.search(line)
        if killed_match:
            ts_match = timestamp_re.match(line)
            if ts_match:
                try:
                    # Parse ISO timestamp
                    ts_str = ts_match.group(1)
                    # Convert to datetime
                    ts = datetime.fromisoformat(ts_str.replace('+', '+'))
                    oom_events.append({
                        'timestamp': ts,
                        'timestamp_epoch': ts.timestamp(),
                        'killed_pid': int(killed_match.group(1)),
                        'killed_name': killed_match.group(2)
                    })
                except ValueError:
                    pass

    if not oom_events:
        print("\nNo OOM events found in the last 7 days.")
        return

    print(f"\nFound {len(oom_events)} OOM event(s)")

    # Load snapshots
    if not SNAPSHOT_FILE.exists():
        print(f"\nNo snapshot file found. Cannot correlate.")
        print("Run snapshot daemon: python3 memory_monitor.py --snapshot")
        return

    snapshots = []
    with open(SNAPSHOT_FILE, 'r') as f:
        for line in f:
            try:
                snapshots.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not snapshots:
        print("\nNo snapshots found in the log file.")
        return

    print(f"Loaded {len(snapshots)} memory snapshot(s)")

    # Correlate each OOM event with nearest snapshot
    for i, event in enumerate(oom_events, 1):
        print(f"\n{'='*70}")
        print(f"OOM EVENT #{i}")
        print(f"{'='*70}")
        print(f"Time:    {event['timestamp']}")
        print(f"Killed:  {event['killed_name']} (PID {event['killed_pid']})")

        # Find closest snapshot before the OOM event
        closest_snap = None
        min_diff = float('inf')

        for snap in snapshots:
            snap_time = snap.get('timestamp_epoch', 0)
            diff = event['timestamp_epoch'] - snap_time

            # Only consider snapshots before or at the OOM event (within 5 min)
            if 0 <= diff < 300 and diff < min_diff:
                min_diff = diff
                closest_snap = snap

        if closest_snap:
            print(f"\nClosest snapshot: {closest_snap['timestamp']} ({min_diff:.0f}s before OOM)")
            print(f"System state: Mem {closest_snap['system']['mem_percent']:.1f}%, "
                  f"Swap {closest_snap['system']['swap_percent']:.1f}%")

            print(f"\nActual memory consumers at time of OOM:")
            print(f"{'#':<3} {'Process':<25} {'Memory MB':>12} {'Swap MB':>10} {'OOM Score':>10}")
            print(f"{'-'*3} {'-'*25} {'-'*12} {'-'*10} {'-'*10}")

            for j, proc in enumerate(closest_snap['top_processes'][:10], 1):
                marker = "→" if proc['name'] == event['killed_name'] else " "
                print(f"{marker}{j:<2} {proc['name']:<25} {proc['memory_mb']:>12.1f} "
                      f"{proc['swap_mb']:>10.1f} {proc.get('oom_score', 'N/A'):>10}")

            # Check if killed process was actually the biggest consumer
            killed_proc = next((p for p in closest_snap['top_processes'] if p['name'] == event['killed_name']), None)
            top_proc = closest_snap['top_processes'][0] if closest_snap['top_processes'] else None

            print(f"\n--- ROOT CAUSE ANALYSIS ---")
            if killed_proc and top_proc:
                if killed_proc['name'] == top_proc['name']:
                    print(f"✓ Correct: {event['killed_name']} was the top memory consumer")
                else:
                    killed_mem = killed_proc['memory_mb']
                    top_mem = top_proc['memory_mb']
                    print(f"⚠ MISMATCH: OOM killed {event['killed_name']} ({killed_mem:.0f} MB)")
                    print(f"            But {top_proc['name']} was using {top_mem:.0f} MB")
                    print(f"            → TRUE CULPRIT was likely {top_proc['name']}")
            elif not killed_proc:
                print(f"⚠ {event['killed_name']} wasn't even in top 20 memory consumers!")
                print(f"  → TRUE CULPRIT was likely {top_proc['name']} ({top_proc['memory_mb']:.0f} MB)")
        else:
            print(f"\nNo snapshot found near this OOM event (within 5 minutes)")
            print("Ensure snapshot daemon was running at the time.")

    # Summary recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDATIONS")
    print(f"{'='*70}")
    print("\n1. Keep the snapshot daemon running to capture memory state:")
    print("   python3 memory_monitor.py --snapshot &")
    print("\n2. To make it persistent, create a systemd service for snapshots")
    print("\n3. When OOM occurs, run this correlation to find the true culprit:")
    print("   python3 memory_monitor.py --correlate-oom")
    print("\n4. Adjust OOM scores for problem processes:")
    print("   echo 1000 | sudo tee /proc/<PID>/oom_score_adj")
    print("="*70)


def protect_session_processes():
    """Configure OOM score adjustments to protect critical session processes."""
    print("="*70)
    print("CONFIGURING OOM PROTECTION FOR SESSION PROCESSES")
    print("="*70)

    # Critical processes to protect (regardless of user)
    protect_patterns = [
        ('systemd', -100, 'User session manager'),
        ('gnome-shell', -100, 'GNOME desktop shell'),
        ('gnome-session', -100, 'GNOME session manager'),
        ('gdm', -100, 'Display manager'),
        ('sshd', -100, 'SSH daemon'),
        ('dbus-daemon', -100, 'D-Bus message bus'),
        ('nautilus', -50, 'File manager'),
    ]

    # Processes to make more killable (browsers)
    prefer_kill_patterns = [
        ('chrome', 300, 'Chrome browser'),
        ('firefox', 300, 'Firefox browser'),
        ('brave', 300, 'Brave browser'),
        ('msedge', 300, 'Edge browser'),
    ]

    current_user = psutil.Process().username()
    protected_count = 0
    adjusted_count = 0
    permission_errors = []

    print(f"\nScanning ALL user processes (running as: {current_user})\n")

    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']
            username = proc.info['username']
            oom_adj_file = f'/proc/{pid}/oom_score_adj'

            # Check if process should be protected
            for pattern, score, description in protect_patterns:
                if pattern in name.lower():
                    try:
                        # Read current score
                        with open(oom_adj_file, 'r') as f:
                            current_score = int(f.read().strip())

                        # Only adjust if not already protected
                        if current_score >= 0:
                            with open(oom_adj_file, 'w') as f:
                                f.write(str(score))
                            print(f"✓ Protected: {name:<25} (PID {pid:<7} User: {username}) - {description}")
                            print(f"  OOM score adjusted: {current_score} → {score}")
                            protected_count += 1
                        elif current_score < -50:
                            # Only mention already-protected if strongly protected
                            print(f"  Already protected: {name:<25} (PID {pid}) - score: {current_score}")
                    except PermissionError:
                        permission_errors.append((name, pid, username))
                    except Exception as e:
                        print(f"✗ Error: {name} (PID {pid}): {e}")
                    break

            # Check if process should be preferred for killing (only for non-root users)
            if username != 'root':
                for pattern, score, description in prefer_kill_patterns:
                    if pattern in name.lower():
                        try:
                            with open(oom_adj_file, 'r') as f:
                                current_score = int(f.read().strip())

                            if current_score < 300:
                                with open(oom_adj_file, 'w') as f:
                                    f.write(str(score))
                                print(f"  Adjusted: {name:<25} (PID {pid:<7} User: {username}) - {description}")
                                print(f"  OOM score: {current_score} → {score} (prefer to kill)")
                                adjusted_count += 1
                        except (PermissionError, Exception):
                            pass  # Silently skip permission errors for browsers
                        break

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Protected {protected_count} critical session process(es)")
    print(f"Adjusted {adjusted_count} browser process(es) to be preferred OOM targets")

    if permission_errors:
        print(f"\n⚠  Permission denied for {len(permission_errors)} process(es):")
        for name, pid, username in permission_errors[:5]:
            print(f"  • {name} (PID {pid}, User: {username})")
        if len(permission_errors) > 5:
            print(f"  ... and {len(permission_errors) - 5} more")
        print("\n  Run with sudo to protect all processes:")
        print(f"  sudo python3 {sys.argv[0]} --protect-session")

    if protected_count == 0 and adjusted_count == 0 and not permission_errors:
        print("\nNo processes were adjusted. This could mean:")
        print("  • Critical processes are already protected")
        print("  • Processes are not currently running")
    elif protected_count > 0 or adjusted_count > 0:
        print("\n✓ Session processes protection configured")
        print("  Critical session processes are protected from OOM killer")
        print("  Browsers will be killed first if system runs out of memory")

    print("\nNote: These adjustments only affect currently running processes.")
    print("New processes will use default OOM scores unless permanently configured.")
    print("\nTo make this permanent, consider:")
    print("  • Running this command at login (add to startup applications)")
    print("  • Creating a systemd service to set OOM scores")
    print("="*70)


def main(args=None):
    """Main monitoring function."""
    # Handle special modes that exit early
    if args:
        # Service management modes
        if args.enable_service:
            enable_service()
            return

        if args.disable_service:
            disable_service()
            return

        if args.service_status:
            service_status()
            return

        if args.logs or args.follow_logs:
            show_logs(follow=args.follow_logs)
            return

        if args.enable_snapshot_daemon:
            enable_snapshot_daemon()
            return

        if args.disable_snapshot_daemon:
            disable_snapshot_daemon()
            return

        if args.snapshot_status:
            snapshot_daemon_status()
            return

        # Analysis and info modes
        if args.analyze_dmesg:
            analyze_dmesg_mode(args.analyze_dmesg)
            return

        if args.analyze_oom is not None:
            analyze_journalctl_oom(args.analyze_oom)
            return

        if args.snapshot:
            run_snapshot_daemon(args.snapshot_interval)
            return

        if args.analyze_snapshots is not None:
            analyze_snapshots_mode(args.analyze_snapshots)
            return

        if args.correlate_oom:
            correlate_oom_with_snapshots()
            return

        if args.show_oom_scores:
            show_oom_scores()
            return

        if args.protect_session:
            protect_session_processes()
            return

        if args.check:
            check_memory_mode()
            return

        if args.list_browsers:
            list_browsers_mode()
            return

        if args.list_tabs:
            list_tabs_mode()
            return

    # Load configuration
    config_path = args.config if args and args.config else None
    config = load_config(config_path)

    # Apply CLI overrides
    if args:
        if args.dry_run:
            config['dry_run'] = True
        if args.threshold is not None:
            config['memory_threshold_percent'] = args.threshold
        if args.swap_threshold is not None:
            config['swap_threshold_percent'] = args.swap_threshold

    logger = setup_logging(config)

    logger.info("="*60)
    logger.info("OOM Tracker starting")

    # Get current user
    current_username = psutil.Process().username()
    logger.info(f"Monitoring processes for user: {current_username}")

    # Check memory and swap usage
    mem_usage = get_memory_usage()
    logger.info(f"Memory usage: {mem_usage['percent']:.1f}% "
                f"(Available: {mem_usage['available_gb']:.1f}GB / "
                f"Total: {mem_usage['total_gb']:.1f}GB)")
    logger.info(f"Swap usage: {mem_usage['swap_percent']:.1f}% "
                f"(Used: {mem_usage['swap_used_gb']:.1f}GB / "
                f"Total: {mem_usage['swap_total_gb']:.1f}GB)")

    mem_threshold = config.get('memory_threshold_percent', 90)
    swap_threshold = config.get('swap_threshold_percent', 50)

    mem_exceeded = mem_usage['percent'] >= mem_threshold
    swap_exceeded = mem_usage['swap_percent'] >= swap_threshold

    if not mem_exceeded and not swap_exceeded:
        logger.info(f"Memory ({mem_usage['percent']:.1f}%) below threshold ({mem_threshold}%), "
                    f"Swap ({mem_usage['swap_percent']:.1f}%) below threshold ({swap_threshold}%). "
                    f"No action needed.")
        return

    # Log which threshold(s) exceeded
    if mem_exceeded:
        logger.warning(f"Memory usage EXCEEDS threshold ({mem_threshold}%)!")
    if swap_exceeded:
        logger.warning(f"Swap usage EXCEEDS threshold ({swap_threshold}%)!")

    # Log top memory and swap consumers
    top_consumers = get_top_memory_consumers(10, sort_by='total')
    logger.info("Top 10 memory/swap consumers:")
    for i, proc in enumerate(top_consumers, 1):
        logger.info(f"  {i}. PID {proc['pid']}: {proc['name']} "
                    f"({proc['username']}) - RAM: {proc['memory_mb']:.1f}MB, "
                    f"Swap: {proc['swap_mb']:.1f}MB, Total: {proc['total_mb']:.1f}MB")

    # Find browser process trees
    browser_trees = find_browser_process_tree(current_username)

    if not browser_trees:
        logger.warning("No browser processes found to kill!")
        logger.warning("Memory pressure exists but no browsers to terminate.")
        return

    # Log all browser instances
    logger.info(f"Found {len(browser_trees)} browser instance(s):")
    for root_pid, tree in browser_trees.items():
        logger.info(f"  {tree['browser_type'].upper()} (PID {root_pid}): "
                    f"{tree['total_memory_mb']:.1f} MB "
                    f"({len(tree['children'])} processes)")

    # Determine kill strategy
    kill_mode = config.get('kill_mode', 'browser').lower()
    dry_run = config.get('dry_run', False)

    if dry_run:
        logger.info("DRY RUN MODE - Will simulate actions without actually killing processes")

    # Strategy B: Kill tabs first
    if kill_mode == 'tab':
        logger.info("Using STRATEGY B: Tab-level killing")
        tabs_killed = kill_tabs_strategy(browser_trees, config, logger, current_username)

        if tabs_killed:
            logger.info("Tab killing completed. Check memory on next cycle.")
        else:
            logger.warning("No eligible tabs to kill, falling back to killing entire browser")
            # Fall back to killing entire browser
            target_pid, target_tree = max(browser_trees.items(),
                                           key=lambda x: x[1]['total_memory_mb'])

            logger.warning(f"Targeting {target_tree['browser_type'].upper()} "
                           f"(PID {target_pid}) using {target_tree['total_memory_mb']:.1f} MB")

            kill_result = kill_browser_instance(
                target_tree,
                config.get('kill_timeout_seconds', 30),
                dry_run=dry_run
            )

            if kill_result['success']:
                logger.info(f"Successfully terminated {kill_result['browser_type'].upper()} "
                            f"(PID {kill_result['root_pid']}) using method: {kill_result['method']}")
                logger.info(f"Freed approximately {kill_result['memory_freed_mb']:.1f} MB "
                            f"across {kill_result['process_count']} processes")
            else:
                logger.error(f"Failed to kill {kill_result['browser_type'].upper()} "
                             f"(PID {kill_result['root_pid']})")
                if 'error' in kill_result:
                    logger.error(f"Error: {kill_result['error']}")

    # Original strategy: Kill entire browser
    else:
        logger.info("Using ORIGINAL STRATEGY: Entire browser killing")
        target_pid, target_tree = max(browser_trees.items(),
                                       key=lambda x: x[1]['total_memory_mb'])

        logger.warning(f"Targeting {target_tree['browser_type'].upper()} "
                       f"(PID {target_pid}) using {target_tree['total_memory_mb']:.1f} MB")

        kill_result = kill_browser_instance(
            target_tree,
            config.get('kill_timeout_seconds', 30),
            dry_run=dry_run
        )

        if kill_result['success']:
            logger.info(f"Successfully terminated {kill_result['browser_type'].upper()} "
                        f"(PID {kill_result['root_pid']}) using method: {kill_result['method']}")
            logger.info(f"Freed approximately {kill_result['memory_freed_mb']:.1f} MB "
                        f"across {kill_result['process_count']} processes")
        else:
            logger.error(f"Failed to kill {kill_result['browser_type'].upper()} "
                         f"(PID {kill_result['root_pid']})")
            if 'error' in kill_result:
                logger.error(f"Error: {kill_result['error']}")

    logger.info("OOM Tracker finished")
    logger.info("="*60)


if __name__ == '__main__':
    try:
        args = setup_argparse()
        main(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
