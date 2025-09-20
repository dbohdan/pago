// pago - a command-line password manager.
//
// License: MIT.
// See the file LICENSE.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"dbohdan.com/pago"
	"dbohdan.com/pago/agent"

	"github.com/alecthomas/kong"
)

type CLI struct {
	// Global options.
	Memlock bool   `env:"${MemlockEnv}" default:"true" negatable:"" help:"Lock agent memory with mlockall(2) (${env})"`
	Socket  string `short:"s" env:"${SocketEnv}" default:"${DefaultSocket}" help:"Agent socket path (${env})"`

	// Commands.
	Run     RunCmd     `cmd:"" help:"Run the agent process"`
	Version VersionCmd `cmd:"" aliases:"v,ver" help:"Print version number and exit"`
}

type RunCmd struct {
	Expire time.Duration `short:"e" default:"0" help:"Agent expiration time (Go duration, 0 to disable)"`
}

func (cmd *RunCmd) Run(cli *CLI) error {
	if cli.Memlock {
		if err := LockMemory(); err != nil {
			pago.PrintError("%v", err)
			os.Exit(pago.ExitMemlockError)
		}
	}

	socketDir := filepath.Dir(cli.Socket)
	if err := os.MkdirAll(socketDir, pago.DirPerms); err != nil {
		return fmt.Errorf("failed to create socket directory: %v", err)
	}

	return agent.Run(cli.Socket, cmd.Expire)
}

type VersionCmd struct{}

func (cmd *VersionCmd) Run(cli *CLI) error {
	fmt.Println(pago.Version)
	return nil
}

func main() {
	var cli CLI

	defaultSocket, err := pago.DefaultSocket()
	if err != nil {
		pago.ExitWithError("%v", err)
	}

	parser := kong.Parse(&cli,
		kong.Name("pago-agent"),
		kong.Description("Password store agent for pago."),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Exit(func(code int) {
			if code != 0 {
				code = 2
			}

			os.Exit(code)
		}),
		kong.Vars{
			"DefaultSocket": defaultSocket,

			"MemlockEnv": pago.MemlockEnv,
			"SocketEnv":  pago.SocketEnv,
		},
	)

	ctx, err := parser.Parse(os.Args[1:])
	if err != nil {
		parser.FatalIfErrorf(err)
	}

	if err := ctx.Run(&cli); err != nil {
		pago.ExitWithError("%v", err)
	}
}
