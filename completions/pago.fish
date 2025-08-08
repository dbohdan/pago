# fish shell completions for pago, a command-line password manager.
#
# License: MIT.
# See the file `LICENSE`.

# Command groups.
set -l add_commands a add
set -l clip_commands c clip
set -l delete_commands d del delete
set -l edit_commands e edit
set -l generate_commands g gen generate
set -l pick_commands p pick
set -l rename_commands mv r rename
set -l show_commands s show
set -l version_commands v ver version
set -g __pago_cmd_groups $add_commands $clip_commands $delete_commands $edit_commands $generate_commands $pick_commands $rename_commands $show_commands $version_commands

function __pago_no_subcommand
    not __fish_seen_subcommand_from $__pago_cmd_groups
end

complete -c pago -f

# Commands without options.
complete -c pago -n __pago_no_subcommand -a find -d "Find entry by name regex"
complete -c pago -n __pago_no_subcommand -a init -d "Create a new password store"
complete -c pago -n __pago_no_subcommand -a rekey -d "Reencrypt all entries with recipients file"
complete -c pago -n __pago_no_subcommand -a rewrap -d "Change the password for the identities file"
complete -c pago -n __pago_no_subcommand -a version -d "Print version number and exit"

# Global options.
complete -c pago -l no-confirm -d "Don't enter passwords twice"
complete -c pago -s d -l dir -d "Store location" -r
complete -c pago -l no-git -d "Don't commit to Git"
complete -c pago -l git-email -d "Email for Git commits" -r
complete -c pago -l git-name -d "Name for Git commits" -r
complete -c pago -s s -l socket -d "Agent socket path" -r
complete -c pago -s v -l verbose -d "Print debugging information"

# Options for the individual commands.
# `add` command options.
complete -c pago -n __pago_no_subcommand -a add -d "Create new password entry"
for cmd in $add_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s l -l length -d "Password length" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pattern -d "Password pattern" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s f -l force -d "Overwrite existing entry"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s i -l input -d "Input the password manually"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s m -l multiline -d "Read password from stdin until EOF"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s r -l random -d "Generate a random password"
end

# `clip` command options.
complete -c pago -n __pago_no_subcommand -a clip -d "Copy entry to clipboard"
for cmd in $clip_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s c -l command -d "Command for copying text from stdin to clipboard" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s t -l timeout -d "Clipboard timeout" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `delete` command options.
complete -c pago -n __pago_no_subcommand -a delete -d "Delete password entry"
for cmd in $delete_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s f -l force -d "Do not ask to confirm"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `edit` command options.
complete -c pago -n __pago_no_subcommand -a edit -d "Edit password entry"
for cmd in $edit_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s f -l force -d "Create the entry if it doesn't exist"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `generate` command options.
complete -c pago -n __pago_no_subcommand -a generate -d "Generate and print password"
for cmd in $generate_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s l -l length -d "Password length" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pattern -d "Password pattern" -r
end

# `pick` command options.
complete -c pago -n __pago_no_subcommand -a pick -d "Show password for a picked entry"
for cmd in $pick_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `rename` command options.
complete -c pago -n __pago_no_subcommand -a rename -d "Rename or move a password entry"
for cmd in $rename_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `show` command options.
complete -c pago -n __pago_no_subcommand -a show -d "Show password for entry or list entries"
for cmd in $show_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end
