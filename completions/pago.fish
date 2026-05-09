# fish shell completions for pago, a command-line password manager.
#
# License: MIT.
# See the file `LICENSE`.

# Command groups.
set -l add_commands a add
set -l clip_commands c clip
set -l copy_commands cp copy duplicate
set -l delete_commands d del delete rm
set -l edit_commands e edit
set -l find_commands f find
set -l generate_commands g gen generate
set -l git_commands git
set -l log_commands log
set -l pick_commands p pick
set -l rekey_commands rekey
set -l rename_commands mv r rename
set -l rewrap_commands rewrap
set -l show_commands s show
set -l version_commands v ver version
set -g __pago_cmd_groups $add_commands $clip_commands $copy_commands $delete_commands $edit_commands $find_commands $generate_commands $git_commands $log_commands $pick_commands $rekey_commands $rename_commands $rewrap_commands $show_commands $version_commands

function __pago_no_subcommand
    not __fish_seen_subcommand_from $__pago_cmd_groups
end

complete -c pago -f

# Commands without options.
complete -c pago -n __pago_no_subcommand -a init -d "Create a new password store"
complete -c pago -n __pago_no_subcommand -a rekey -d "Reencrypt all entries with recipients file"
complete -c pago -n __pago_no_subcommand -a rewrap -d "Change the password for the identities file"

# Global options.
complete -c pago -s a -l agent -d "Agent executable" -r
complete -c pago -l confirm -d "Enter passwords twice"
complete -c pago -l no-confirm -d "Don't enter passwords twice"
complete -c pago -s d -l dir -d "Store location" -r
complete -c pago -s e -l expire -d "Agent expiration time" -r
complete -c pago -l git -d "Commit to Git"
complete -c pago -l no-git -d "Don't commit to Git"
complete -c pago -l git-email -d "Email for Git commits" -r
complete -c pago -l git-name -d "Name for Git commits" -r
complete -c pago -l memlock -d "Lock agent memory"
complete -c pago -l no-memlock -d "Don't lock agent memory"
complete -c pago -l passphrase-fd -d "Read the master password from this file descriptor instead of prompting" -r
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
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s t -l trim -d "Strip trailing newline characters from the password"
end

# `clip` command options.
complete -c pago -n __pago_no_subcommand -a clip -d "Copy entry to clipboard"
for cmd in $clip_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s c -l command -d "Command for copying text from stdin to clipboard" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s k -l key -d "Retrieve a key from a TOML entry" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s t -l timeout -d "Clipboard timeout" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `copy` command options.
complete -c pago -n __pago_no_subcommand -a copy -d "Duplicate a password entry"
for cmd in $copy_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s f -l force -d "Overwrite existing destination entry"
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
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -l mouse -d "Enable mouse support in the editor"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -l no-mouse -d "Disable mouse support in the editor"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -l save -d "Allow saving edited entry"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -l no-save -d "Disallow saving edited entry"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `find` command options.
complete -c pago -n __pago_no_subcommand -a find -d "Find entry by name regex"
for cmd in $find_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s j -l json -d "Output as a JSON array"
end

# `generate` command options.
complete -c pago -n __pago_no_subcommand -a generate -d "Generate and print password"
for cmd in $generate_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s l -l length -d "Password length" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pattern -d "Password pattern" -r
end

# `git` command options.
complete -c pago -n __pago_no_subcommand -a git -d "Run Git inside the store directory"
for cmd in $git_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -l git-command -d "Git command to invoke" -r
end

# `log` command options.
complete -c pago -n __pago_no_subcommand -a log -d "Show recent commits in the store's Git history"
for cmd in $log_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s n -l max-count -d "Maximum number of commits to show" -r
end

# `pick` command options.
complete -c pago -n __pago_no_subcommand -a pick -d "Show password for a picked entry"
for cmd in $pick_commands
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s j -l json -d "Output result as JSON"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s k -l key -d "Retrieve a key from a TOML entry" -r
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
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s j -l json -d "Output result as JSON"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s k -l key -d "Retrieve a key from a TOML entry" -r
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s K -l keys -d "List keys in a TOML entry"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -s p -l pick -d "Pick entry using fuzzy finder"
    complete -c pago -n "__fish_seen_subcommand_from $cmd" -a "(pago find)"
end

# `version` command options.
complete -c pago -n __pago_no_subcommand -a version -d "Print version number and exit"
