# pago

**pago** is a command-line password manager.
It provides the following in a single binary:
- [age](https://github.com/FiloSottile/age) public-key and password encryption
- Git version control of the password store ([go-git](https://github.com/go-git/go-git))
- A fuzzy finder similar to [fzf](https://github.com/junegunn/fzf) for choosing entries ([go-fuzzyfinder](https://github.com/ktr0731/go-fuzzyfinder))
- A multiline text editor for editing encrypted data without writing it to disk ([bubbles/textarea](https://github.com/charmbracelet/bubbles))

pago is currently in the [alpha phase](https://en.wikipedia.org/wiki/Software_release_life_cycle#Alpha) of development.
Expect uncaught security vulnerabilities and bugs that cause data loss.

## Description

pago encrypts passwords with one or more public keys using [age](https://github.com/FiloSottile/age) (pronounced with a hard "g").
The public keys are called "recipients".
A private key matching any of the recipient public keys can decrypt the password.
The private keys are called "identities".
The file with the identities is encrypted with a password, also using age.

pago implements an agent like [ssh-agent](https://en.wikipedia.org/wiki/Ssh-agent) or [gpg-agent](https://www.gnupg.org/documentation/manuals/gnupg/Invoking-GPG_002dAGENT.html).
The agent caches the identities used to decrypt the passwords.
This mean you don't have to enter the master password again during a session.
pago starts the agent the first time you enter the master password.
You can also start and stop the agent manually.

The pago password store format is compatible with [passage](https://github.com/FiloSottile/passage).
It has the following differences:

- The pago directory is located in `${XDG_DATA_HOME}/pago/`, while passage uses `~/.passage/`
- passage supports an encrypted or an unencrypted identities file; pago only supports encrypted

### Motivation and alternatives

My primary password manager is [KeePassXC](https://github.com/keepassxreboot/keepassxc).
I use a secondary password manager to access a subset of secrets in cron jobs and scripts and on headless remote systems.

For a time, I used [`pass`](https://www.passwordstore.org/) for this.
While I liked the design of `pass` and found it pleasant to use, I didn't like setting up GPG on a new system.
I went looking for a `pass` replacement based on age
because I had replaced GPG with age for encrypting files.
The following is the shortlist of password managers I compiled before I decided to work on pago.
It includes an explanation for why I didn't adopt them.

First, I needed the identities encrypted at rest and usable without reentering the password.
This ruled out [passage](https://github.com/FiloSottile/passage), which had no an agent, and [pa](https://github.com/biox/pa), which didn't support encryption for the identities file.
[kbs2](https://github.com/woodruffw/kbs2) didn't integrate with Git.
[seniorpw](https://gitlab.com/retirement-home/seniorpw) matched all of my criteria and was the closest to `pass`.
It is what I would most likely be using if I didn't decide to develop my own.

All of the above password managers are worth your attention.
For more options, see ["Awesome age"](https://github.com/FiloSottile/awesome-age).

### History

pago is a heavily modified fork of [pash](https://github.com/dylanaraps/pash) (archived).
It has been ported from POSIX shell to Tcl to Go.
In the middle of this, it switched from [GPG](https://gnupg.org/) to age.

## Installation

You will need Go 1.22 to install pago.
Once Go is installed on your system, run the following command:

```
go install github.com/dbohdan/pago@master
```

## Supported platforms

- pago is used by the developer on Linux, NetBSD, and OpenBSD.
- pago is automatically tested on FreeBSD and macOS.
- pago compiles on Windows.

When pago is built natively for Windows, it has no agent.
The test suite also doesn't work on Windows.
Windows users interested in pago should prefer running it in [WSL](https://en.wikipedia.org/wiki/Windows_Subsystem_for_Linux).

## Usage

### Initialize the password store

```shell
pago init
```

This will create a new password store, prompt you for a master password, and commit the recipients file to Git.

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

# Read a multiline secret.
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

# Find entires by a name regular expression.
pago find fo

# Select and entry interactively using a fuzzy finder
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

### Agent

The agent keeps your identities in memory to avoid repeated password prompts.

```shell
# Start automatically when needed (recommended).
pago show foo/bar

# Start manually.
pago agent start

# Run without an agent.
pago -s '' show foo/bar

# Shut down.
pago agent stop
```

### Environment variables

- `PAGO_CLIP`:
  The command to use to copy the password to the clipboard.
  The default differs by platform.
  On Linux and BSD, it is `xclip -in -selection clip`.
- `PAGO_CONFIRM`:
  Whether pago should ask yes-no questions.
  `0` means pago will assume "yes".
- `PAGO_DIR`:
  The pago data directory location.
  Defaults to `~/.local/share/pago` on Linux and BSD.
- `PAGO_GIT`:
  Whether to use Git
- `PAGO_LENGTH`:
  The default length of random passwords
- `PAGO_PATTERN`:
  The default character pattern (regular expression) for random passwords
- `PAGO_SOCK`:
  The agent socket path
- `PAGO_TIMEOUT`:
  The default clipboard timeout

### Interactive editor

The editor for the `edit` command editor includes the default [bubbles/textarea key bindings](https://github.com/charmbracelet/bubbles/blob/8624776d4572078ae6ff098d454c719047f9eb83/textarea/textarea.go#L71).

#### Session

- **Ctrl+D**: Save and exit
- **Esc**/**Ctrl+C**: Exit without saving

#### Navigation

- **←**/**Ctrl+B**: Move cursor left by one character
- **→**/**Ctrl+F**: Move cursor right by one character
- **Alt+←**/**Alt+B**: Move cursor left by one word
- **Alt+→**/**Alt+F**: Move cursor right by one word
- **↑**/**Ctrl+P**: Move cursor up a line
- **↓**/**Ctrl+N**: Move cursor down a line
- **Home**/**Ctrl+A**: Move to line start
- **End**/**Ctrl+E**: Move to line end
- **Alt+<**/**Ctrl+Home**: Move to beginning of input
- **Alt+>**/**Ctrl+End**: Move to end of input

#### Editing

- **Backspace**/**Ctrl+H**: Delete character before cursor
- **Delete**/**Ctrl+D**: Delete character after cursor
- **Alt+Backspace**/**Ctrl+W**: Delete word before cursor
- **Alt+Delete**/**Alt+D**: Delete word after cursor
- **Ctrl+K**: Delete all text after cursor
- **Ctrl+U**: Delete all text before cursor
- **Enter**/**Ctrl+M**: Insert newline
- **Ctrl+V**: Paste from clipboard

#### Text transformation

- **Alt+C**: Capitalize word forward
- **Alt+L**: Lowercase word forward
- **Alt+U**: Uppercase word forward
- **Ctrl+T**: Transpose characters at cursor

## License

MIT.
See the file [`LICENSE`](LICENSE).
