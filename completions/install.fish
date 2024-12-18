#! /usr/bin/env fish
# fish shell completions for pago, a command-line password manager.
#
# License: MIT.
# See the file `LICENSE`.

cd "$(path dirname "$(status filename)")"

set --local src pago.fish
set --local dst $__fish_config_dir/completions/

printf 'copying "%s" to "%s"\n' $src $dst

cp $src $dst
