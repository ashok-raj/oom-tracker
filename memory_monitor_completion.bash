# Bash completion for memory_monitor.py
# Add to ~/.bash_completion or source directly

_memory_monitor() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--version --config --dry-run --threshold --swap-threshold --check --short
          --list-browsers --list-tabs --analyze-dmesg --analyze-oom --snapshot
          --snapshot-interval --analyze-snapshots --correlate-oom --protect-session
          --show-oom-scores --enable-service --disable-service --service-status
          --logs --follow-logs --enable-snapshot-daemon --disable-snapshot-daemon
          --snapshot-status"

    case "${prev}" in
        --config|--analyze-dmesg)
            # File completion
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --threshold|--swap-threshold|--snapshot-interval)
            # Integer completion (suggest common values)
            COMPREPLY=( $(compgen -W "50 60 70 75 80 85 90 95" -- "${cur}") )
            return 0
            ;;
        --analyze-oom|--analyze-snapshots)
            # Time values
            COMPREPLY=( $(compgen -W "1 7 14 30 60 120" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi
}

complete -F _memory_monitor memory_monitor.py
complete -F _memory_monitor ./memory_monitor.py
