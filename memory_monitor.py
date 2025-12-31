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
VERSION = '1.2.0'
SCRIPT_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = SCRIPT_DIR / 'config.yaml'
LOG_DIR = SCRIPT_DIR / 'logs'
LOG_FILE = LOG_DIR / 'memory-monitor.log'

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
        '--analyze-dmesg',
        metavar='PATH',
        type=str,
        help='Analyze gzipped or plain text dmesg log file for OOM events and likely causes'
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

    args = parser.parse_args()

    # Validate threshold if provided
    if args.threshold is not None:
        if args.threshold < 0 or args.threshold > 100:
            parser.error('--threshold must be between 0 and 100')

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
    # Calculate based on available memory
    # This accounts for buffers/cache that can be reclaimed
    usage_percent = 100.0 - (mem.available / mem.total * 100.0)
    return {
        'total_gb': mem.total / (1024**3),
        'available_gb': mem.available / (1024**3),
        'used_gb': mem.used / (1024**3),
        'percent': usage_percent
    }


def get_top_memory_consumers(limit=5):
    """Get top N memory-consuming processes."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info']):
        try:
            info = proc.info
            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'username': info['username'],
                'memory_mb': info['memory_info'].rss / (1024**2)
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    processes.sort(key=lambda x: x['memory_mb'], reverse=True)
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
    print("="*60)
    print("MEMORY STATUS CHECK")
    print("="*60)

    # Get memory usage
    mem_usage = get_memory_usage()
    print(f"\nMemory Usage: {mem_usage['percent']:.1f}%")
    print(f"  Total:     {mem_usage['total_gb']:.2f} GB")
    print(f"  Used:      {mem_usage['used_gb']:.2f} GB")
    print(f"  Available: {mem_usage['available_gb']:.2f} GB")

    # Get top memory consumers
    print(f"\nTop 5 Memory Consumers:")
    top_consumers = get_top_memory_consumers(5)
    for i, proc in enumerate(top_consumers, 1):
        print(f"  {i}. PID {proc['pid']:>6}: {proc['name']:<20} "
              f"({proc['username']:<10}) - {proc['memory_mb']:>8.1f} MB")

    # Check against threshold
    config = load_config()
    threshold = config.get('memory_threshold_percent', 90)
    print(f"\nConfigured Threshold: {threshold}%")

    if mem_usage['percent'] >= threshold:
        print(f"STATUS: EXCEEDS threshold by {mem_usage['percent'] - threshold:.1f}%")
        print("        (Monitor would take action if running normally)")
    else:
        print(f"STATUS: Below threshold by {threshold - mem_usage['percent']:.1f}%")

    print("="*60)


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

        # Analysis and info modes
        if args.analyze_dmesg:
            analyze_dmesg_mode(args.analyze_dmesg)
            return

        if args.check:
            check_memory_mode()
            return

        if args.list_browsers:
            list_browsers_mode()
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

    logger = setup_logging(config)

    logger.info("="*60)
    logger.info("OOM Tracker starting")

    # Get current user
    current_username = psutil.Process().username()
    logger.info(f"Monitoring processes for user: {current_username}")

    # Check memory usage
    mem_usage = get_memory_usage()
    logger.info(f"Memory usage: {mem_usage['percent']:.1f}% "
                f"(Available: {mem_usage['available_gb']:.1f}GB / "
                f"Total: {mem_usage['total_gb']:.1f}GB)")

    threshold = config.get('memory_threshold_percent', 90)

    if mem_usage['percent'] < threshold:
        logger.info(f"Memory usage below threshold ({threshold}%). No action needed.")
        return

    logger.warning(f"Memory usage EXCEEDS threshold ({threshold}%)!")

    # Log top memory consumers
    top_consumers = get_top_memory_consumers(5)
    logger.info("Top 5 memory consumers:")
    for i, proc in enumerate(top_consumers, 1):
        logger.info(f"  {i}. PID {proc['pid']}: {proc['name']} "
                    f"({proc['username']}) - {proc['memory_mb']:.1f} MB")

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

    # Find the browser instance with highest memory usage
    target_pid, target_tree = max(browser_trees.items(),
                                   key=lambda x: x[1]['total_memory_mb'])

    logger.warning(f"Targeting {target_tree['browser_type'].upper()} "
                   f"(PID {target_pid}) using {target_tree['total_memory_mb']:.1f} MB")

    # Kill the browser
    dry_run = config.get('dry_run', False)
    if dry_run:
        logger.info("DRY RUN MODE - Would kill browser but not actually doing it")

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
