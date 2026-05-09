# Bash completions for pago, a command-line password manager.
#
# License: MIT.
# See the file `LICENSE`.

# Command aliases and options.
_pago_main_commands="add clip copy delete edit find generate git init log pick rekey rename rewrap show version"
_pago_global_options="-a --agent --confirm --no-confirm -d --dir -e --expire --git --no-git --git-email --git-name --memlock --no-memlock --passphrase-fd -s --socket -v --verbose"

# Subcommand options.
declare -A _pago_subcommand_options
_pago_subcommand_options[add]="-l --length -p --pattern -f --force -i --input -m --multiline -r --random -t --trim"
_pago_subcommand_options[clip]="-c --command -k --key -p --pick -t --timeout"
_pago_subcommand_options[copy]="-f --force"
_pago_subcommand_options[delete]="-f --force -p --pick"
_pago_subcommand_options[edit]="-f --force --mouse --no-mouse -p --pick --save --no-save"
_pago_subcommand_options[find]="-j --json"
_pago_subcommand_options[generate]="-l --length -p --pattern"
_pago_subcommand_options[git]="--git-command"
_pago_subcommand_options[log]="-n --max-count"
_pago_subcommand_options[pick]="-j --json -k --key"
_pago_subcommand_options[show]="-j --json -k --key -K --keys -p --pick"

# Fetch entries dynamically using `pago find`.
_pago_find_entries() {
    command -v pago &>/dev/null && pago find 2>/dev/null
}

# Complete global options.
_pago_complete_global_options() {
    COMPREPLY=($(compgen -W "$_pago_global_options" -- "$cur"))
}

# Complete options for a given subcommand.
_pago_complete_subcommand_options() {
    local options=${_pago_subcommand_options[$1]}
    COMPREPLY=($(compgen -W "$options" -- "$cur"))

    # Add dynamic completions (entries) if not starting with a dash.
    if [[ $cur != -* ]]; then
        COMPREPLY+=($(compgen -W "$(_pago_find_entries)" -- "$cur"))
    fi
}

_pago_complete() {
    local cur cword subcommand
    _init_completion || return

    cur="${COMP_WORDS[COMP_CWORD]}"
    cword=$COMP_CWORD
    subcommand="${COMP_WORDS[1]}"

    if [[ $cword -eq 1 ]]; then
        # Complete the main subcommands in the first position.
        COMPREPLY=($(compgen -W "$_pago_main_commands $_pago_global_options" -- "$cur"))
    else
        # Complete subcommands or global options.
        case "$subcommand" in
        a | add | c | clip | cp | copy | duplicate | d | del | delete | rm | e | edit | f | find | g | gen | generate | git | log | p | pick | r | rename | mv | s | show)
            _pago_complete_subcommand_options "$subcommand"
            ;;
        *)
            # Fallback to global options when there is no valid subcommand.
            _pago_complete_global_options
            ;;
        esac
    fi
}

complete -F _pago_complete pago
