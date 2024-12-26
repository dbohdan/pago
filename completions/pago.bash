# Bash completions for pago, a command-line password manager.
#
# License: MIT.
# See the file `LICENSE`.

# Command aliases and options.
_pago_main_commands="add clip delete edit find generate init pick rekey rewrap show version"
_pago_global_options="-d --dir --no-confirm --no-git --git-email --git-name -s --socket -v --verbose"

# Subcommand options.
declare -A _pago_subcommand_options
_pago_subcommand_options[add]="-l --length -p --pattern -f --force -i --input -m --multiline -r --random"
_pago_subcommand_options[clip]="-c --command -p --pick -t --timeout"
_pago_subcommand_options[delete]="-f --force -p --pick"
_pago_subcommand_options[edit]="-f --force -p --pick"
_pago_subcommand_options[generate]="-l --length -p --pattern"
_pago_subcommand_options[show]="-p --pick"

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
            a|add|c|clip|d|del|delete|rm|e|edit|g|gen|generate|p|pick|s|show)
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
