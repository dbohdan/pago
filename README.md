# pago

> [!WARNING]
> **pago is in [beta](https://en.wikipedia.org/wiki/Software_release_life_cycle#Beta).**
> Using pago carries a greater risk of bugs, security vulnerabilities, and data loss than using mature software.

**pago** is a command-line password manager.
It provides the following in a single binary:
- [age](https://github.com/FiloSottile/age) public-key and password encryption
- Git version control of the password store ([go-git](https://github.com/go-git/go-git))
- A fuzzy finder similar to [fzf](https://github.com/junegunn/fzf) for choosing entries ([go-fuzzyfinder](https://github.com/ktr0731/go-fuzzyfinder))
- A multiline text editor for editing encrypted data without writing it to disk ([tview](https://github.com/rivo/tview))

## Description

pago encrypts passwords with one or more public keys using [age](https://github.com/FiloSottile/age) (pronounced with a hard "g").
The public keys are called "recipients".
Recipients can be:
- age recipients
- SSH public keys

A private key matching one of the recipient public keys can decrypt the password entry.
The private keys are called "identities".
Identities can be:
- age identities
- SSH private keys

The file with the identities is encrypted with a password, also using age.

pago implements an agent like [ssh-agent](https://en.wikipedia.org/wiki/Ssh-agent) or [gpg-agent](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-GPG_002dAGENT.html).
The agent caches the identities.
This means you don't have to enter the master password again during a session.
pago starts the agent the first time you enter the master password.
You can also start and stop the agent manually.

The pago password store format is compatible with [passage](https://github.com/FiloSottile/passage).
It has the following differences:

- The pago directory is located at `$XDG_DATA_HOME/pago/`, while passage uses `~/.passage/`
- passage supports an encrypted or an unencrypted identities file; pago only supports encrypted

## Threat model

An attacker who gets ahold of your pago directory but not the master password should be unable to access the passwords stored in pago except by [brute-forcing](https://en.wikipedia.org/wiki/Brute-force_attack) the master password.

## Motivation and alternatives

My primary password manager is [KeePassXC](https://github.com/keepassxreboot/keepassxc).
I use a secondary password manager to access a subset of secrets in cron jobs and scripts and on headless remote systems.

I used [`pass`](https://www.passwordstore.org/) for this for a time.
While I liked the design of `pass` and found it pleasant to use, I didn't like setting up GPG on a new system.
I went looking for a `pass` replacement based on age
because I had replaced GPG with age for encrypting files.
The following is the late-2024 shortlist of password managers I compiled before I decided to work on pago.
It includes explanations for why I didn't adopt them.

First, I needed the identities encrypted at rest and usable without reentering the password.
This ruled out [passage](https://github.com/FiloSottile/passage), which had no agent, and [pa](https://github.com/biox/pa), which didn't support encryption for the identities file.
[kbs2](https://github.com/woodruffw/kbs2) didn't integrate with Git.
[seniorpw](https://gitlab.com/retirement-home/seniorpw) matched all of my criteria and was the closest to `pass`.
It is what I would most likely be using if I didn't decide to develop my own.
The [`-k`/`--key` feature](https://gitlab.com/retirement-home/seniorpw#editshowmoveremove-a-password) in seniorpw later inspired [TOML entries](#toml-entries) and the approach to [TOTP](#totp).

All of the above password managers are worth your attention.
For more options, see ["Awesome age"](https://github.com/FiloSottile/awesome-age).

## History

pago is a heavily modified fork of [pash](https://github.com/dylanaraps/pash) (archived).
It has been ported from POSIX shell to Tcl to Go and from [GPG](https://gnupg.org/) to age.

## Installation

You will need Go 1.24 or later to install pago.
Once Go is installed on your system, run the following commands:

```shell
# pago and pago-agent are two separate binaries.
# You should install both unless you have a specific reason not to.
go install dbohdan.com/pago/cmd/...@latest
```

Shell completion files for Bash and fish are available in [`completions/`](completions/).
To install completions for fish, clone the repository and run `install.fish`.

You may need to allow pago-agent to [**lock enough memory**](#memory-locking).

## Supported platforms

- pago is used by the developer on Linux, NetBSD, and (rarely) OpenBSD.
- pago is automatically tested on FreeBSD and macOS.
- pago does not build on Windows.

The pago agent and test suite don't work on Windows.
Instead of offering a partial and untested Windows build, the project doesn't support Windows.
Windows users interested in pago are encouraged to try it in [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux).

## Usage

### Initialize the password store

```shell
pago init
```

This will create a new password store, prompt you for a master password, and commit the recipients file to Git.

### Using SSH keys

To use pago with an SSH key as an identity, follow these steps.
Back up your `identities` file and install age for the command line before proceeding.

Note that the SSH key must not be encrypted, i.e., must not have a password.
If necessary, remove the password with `ssh-keygen`.
pago encrypts `identities` with a password using age encryption.

You may wish to work with secrets in memory or on an encrypted disk.
On Linux with glibc, you normally have `/dev/shm/` available as temporary in-memory storage.

1. Add your SSH _public_ key to `.age-recipients`.
You can have multiple recipients.

```shell
# Repeat for every SSH public key.
cat ~/.ssh/id_ed25519.pub >> ~/.local/share/pago/store/.age-recipients

# Re-encrypt the password entries to the new recipients.
pago rekey
```

2. Add the corresponding SSH _private_ keys to the encrypted identities file.
This is not automated and requires decrypting the file manually using the `age` command.
We are going to use a directory in `/dev/shm/` in this example.

```shell
# Edit the identities file.
mkdir -p "/dev/shm/pago-$USER-temp/"
age -d -o "/dev/shm/pago-$USER-temp/identities" ~/.local/share/pago/identities

# Repeat for every SSH private key.
# Ensure a line break.
echo >> "/dev/shm/pago-$USER-temp/identities"
cat ~/.ssh/id_ed25519 >> "/dev/shm/pago-$USER-temp/identities"
age -a -e -p -o ~/.local/share/pago/identities "/dev/shm/pago-$USER-temp/identities"

# Restart the agent to load the new identities.
pago agent restart
```

### Add passwords

```shell
# Either generate or input a password.
pago add foo/bar

# Generate a random password.
pago add -r foo/bar

# Specify a custom length and character pattern (regular expression).
pago add -l 32 -p '[A-Za-z0-9#$%]' foo/bar

# Input your own password.
pago add -i foo/bar

# Read a multiline secret from stdin.
# This is useful for storing age keys or structured data.
# See the "TOML entries" section for more on the latter.
age-keygen | pago add -m foo/bar
```

Adding a password creates a Git commit by default.

### Access passwords

```shell
# Show a password.
pago show foo/bar

# Copy to clipboard (clears after 30 seconds).
pago clip foo/bar

# Copy with a custom timeout (in seconds; 0 to disable).
pago clip -t 20 foo/bar

# List all entries organized in a tree.
pago show

# List entries with a name that matches a regular expression.
pago find fo

# Select an entry interactively using a fuzzy finder.
pago show --pick

# The same as `pago show --pick foo`. Starts the search with `foo`.
pago pick foo
```

### Edit passwords

```shell
# Edit a password that already exists.
pago edit foo/bar

# Create a password if it doesn't exist.
pago edit foo/new -f
```

### Generate passwords

```shell
# Generate a password without saving it.
pago generate

# Customize the length and pattern.
pago generate --length 16 --pattern '[a-z0-9]'
```

### Delete passwords

```shell
# Delete with confirmation.
pago delete foo/bar

# Force delete without confirmation.
pago delete -f foo/bar

# Pick what password to delete using a fuzzy finder.
pago delete -p foo/bar
```

By default, this will commit the deletion to Git.

### Rename passwords

```shell
# Rename an entry.
pago rename foo/bar foo/baz

# Move an entry to a new directory.
pago rename foo/baz qux/quux
```

This creates a Git commit by default.

### TOML entries

pago can store and retrieve structured data in the [TOML](https://toml.io/) format.
This is useful for storing multiple related values in a single entry, such as API keys, usernames, and URLs.

To create a TOML entry, use `pago add --multiline` and provide TOML content on standard input.
The content must start with the string `# TOML`.

```shell
pago add -m services/my-api <<EOF
# TOML
user = "jdoe"
password = "abcdef"
token = "tok-123"
url = "https://api.example.com"
numbers = [1, 1, 2, 3, 5]
EOF
```

When you `show` or `clip` a TOML entry without specifying a key, pago will use a default key.
The default key is `password`.
You can specify a different default key by adding a key `default` to the TOML entry.

```shell
pago add -m services/my-api-custom-default <<EOF
# TOML
default = "api-key"
api-key = "xyz-456"
EOF

pago show services/my-api-custom-default
# => xyz-456
```

You can retrieve other values from the TOML entry using the `-k`/`--key` option with the commands `show`, `clip`, and `pick`, or with the `key` command.

```shell
# Show the user from the TOML entry.
pago show -k user services/my-api
# => jdoe

# The `key` command is a shortcut for `show --key`.
pago key services/my-api user
# => jdoe

# Show an array.
pago show -k numbers services/my-api
# => [1, 1, 2, 3, 5]

# Copy the key to the clipboard.
pago clip -k key services/my-api
```

When an entry is parsed as TOML, pago can retrieve scalar values (strings, numbers, booleans) and arrays of scalars.
Arrays and scalars other than strings are encoded as TOML for output.
pago cannot retrieve tables.

### TOTP

pago can generate [time-based one-time passwords (TOTP)](https://en.wikipedia.org/wiki/Time-based_one-time_password) from a [TOML entry](#toml-entries).
To use this feature, store the `otpauth://` URI in a key named `otp`.
The entry must start with `# TOML`.

```shell
pago add -m services/my-service <<EOF
# TOML
user = "jdoe"
otp = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
EOF
```

When you use `show` or `clip` with the key `otp`, pago will generate and output a TOTP code.

```shell
# Show the TOTP code.
pago show -k otp services/my-service
# => 123456

# Copy the TOTP code to the clipboard.
pago clip -k otp services/my-service
```

### Agent

The agent keeps your identities in memory to avoid repeated password prompts.
By default, the agent runs until manually stopped, but you can configure it to automatically expire after a period of inactivity.

```shell
# Start the agent automatically when needed.
pago show foo/bar

# Start manually.
pago agent start

# Start with automatic expiration after 1 hour of inactivity.
pago agent start --expire 1h

# By default, the agent locks its memory to prevent secrets from being written to swap.
# You may need to run the command `ulimit -l 100000` to let it lock enough memory.
# Alternatively, you can disable memory locking
# with the environment variable `PAGO_MEMLOCK=0` or the option  `--no-memlock`.
pago agent start --no-memlock

# Run without an agent.
pago -s '' show foo/bar

# Shut down.
pago agent stop
```

### Memory locking

pago-agent defaults to [locking the process memory](https://pubs.opengroup.org/onlinepubs/9699919799/functions/mlockall.html) to prevent secrets from being written to swap.
Secrets can be recovered from unencrypted swap that was not erased at system shutdown.

pago-agent uses up to 100 MiB of memory on systems where it has been tested.
Most operating systems don't allow a process to lock this much memory by default.
Additionally, on Free/Net/OpenBSD, the agent apparently needs the limit on locked memory to exceed its virtual memory even though only around 100 MiB is reserved.
The amount of virtual memory can be over 1 GiB.
(You don't lose 1 GiB of memory.)
Configure your system to allow this or set the environment variable `PAGO_MEMLOCK=0` to disable locking.

Here is how to allow users to lock more memory on different operating systems.
In these examples, we set the limit to 8 GiB.

#### Linux (systemd)

1. Create `/etc/systemd/system.conf.d/` if it doesn't exist.
2. Edit `/etc/systemd/system.conf.d/limits.conf` to contain the following:

```ini
[Manager]
DefaultLimitMEMLOCK=8G
```

3. Restart your user session.

#### Linux (other init systems)

1. Edit `/etc/security/limits.conf` and add this line:

```none
* hard memlock 8589934592
```

2. Restart your user session.

#### Free/Net/OpenBSD

1. Edit `/etc/login.conf` and update the default value of `memorylocked`:

```
default:\
	[...]
	:memorylocked=8G:\
	[...]
```

2. On FreeBSD only, run the following command as root:

```shell
cap_mkdb /etc/login.conf
```

3. Restart your user session.

### Environment variables

- `PAGO_AGENT`:
  The agent executable
- `PAGO_CLIP`:
  The command to use to copy text to the clipboard.
  The default differs by platform:
    - Android: `termux-clipboard-set`
    - Linux and BSD: `xclip -in -selection clip`
    - macOS: `pbcopy`
- `PAGO_CONFIRM`:
  Whether pago should ask yes-no questions.
  `0` means pago will assume "yes".
- `PAGO_DIR`:
  The pago data directory location.
  Defaults to:
    - Linux and BSD: `~/.local/share/pago`
    - macOS: `~/Library/Application Support/pago`
- `PAGO_EXPIRE`:
  Agent expiration time after which it will automatically shut down ([Go duration string](https://pkg.go.dev/time#ParseDuration); for example, `1h30m`).
  Default: no expiration.
- `PAGO_GIT`:
  Whether to use Git
- `PAGO_LENGTH`:
  The default length of random passwords
- `PAGO_MEMLOCK`:
  Whether the agent should lock its memory using [mlockall(2)](https://pubs.opengroup.org/onlinepubs/9799919799/functions/mlockall.html) to prevent secrets from being written to swap.
  `0` to disable.
- `PAGO_PATTERN`:
  The default character pattern (regular expression) for random passwords
- `PAGO_SOCK`:
  The agent socket path.
  The default path is determined by trying candidate paths until the parent directory of the pago directory exists.
    - Linux and BSD:
      - `$XDG_RUNTIME_DIR/pago/socket`
      - `/var/run/xdg/$USER/pago/socket` on FreeBSD only
      - `/run/user/$UID/pago/socket`
      - `/var/run/user/$UID/pago/socket`
      - `${TMPDIR:-/tmp}/pago-${USER}/socket`
    - macOS:
      - `${TMPDIR:-/tmp}/pago-${USER}/socket`
- `PAGO_TIMEOUT`:
  The default timeout to clear the clipboard

### Interactive editor

![Screenshot of the editor in a terminal showing a TOML entry.
The TOML entry has a password "hunter2" and a test TOTP URL.](editor.png)

The editor uses a text area from the [tview](https://github.com/rivo/tview) library.
It has the following key bindings:

#### Session

- **Ctrl+C**: Exit without saving
- **Ctrl+D**: Save and exit

#### Navigation

- **←**: Move left one character
- **→**: Move right one character
- **↑**: Move up one row
- **↓**: Move down one row
- **Home**/**Ctrl+A**: Move to the start of the line
- **End**/**Ctrl+E**: Move to the end of the line
- **PgUp**/**Ctrl+B**: Page up
- **PgDn**/**Ctrl+F**: Page down
- **Ctrl+←**/**Alt+B**: Move to the start of the word
- **Ctrl+→**/**Alt-F**: Move to the end of the word
<!-- - **Ctrl+Home**: Move to the start of the text -->
<!-- - **Ctrl+End**: Move to the end of the text -->

#### Editing

- **Enter**: Insert newline
- **Tab**: Insert tab (`\t`)
- **Backspace**/**Ctrl+H**: Delete the previous character
- **Delete**: Delete the next character
- **Alt+Backspace**: Delete the previous word
- **Ctrl+W**: Delete back to the start of the word
- **Ctrl+K**: Delete to the end of the line
- **Ctrl+U**: Delete the entire line

#### Selection

- **Shift** + navigation key: Extend selection
- **Ctrl+L**: Select the entire text
- Mouse drag: Select text
- Left double-click: Select a word

#### Clipboard

The editor clipboard is synchronized with the system clipboard.

- **Ctrl+Q**: Copy selected text
- **Ctrl+X**: Cut selected text
- **Ctrl+V**: Paste from the clipboard

#### Undo/Redo

- **Ctrl+Z**: Undo
- **Ctrl+Y**: Redo

## License

MIT.
See the file [`LICENSE`](LICENSE).
