package main

import (
	"errors"
	"flag"
	"github.com/genshen/cmds"
	_ "github.com/rep1ace/wssocks/cmd/client"
	_ "github.com/rep1ace/wssocks/cmd/server"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	log "github.com/sirupsen/logrus"
	//_ "github.com/rep1ace/wssocks/version"
	_ "github.com/rep1ace/wssocks-plugin-smu/wssocks-ustb/version"
)

// Register USTB VPN client flags for the supervised client command.
func init() {
	vpn.NewUstbVpnCli()
}

func main() {
	cmds.SetProgramName("wssocks-ustb")
	if err := cmds.Parse(); err != nil {
		if !errors.Is(err, flag.ErrHelp) && !errors.Is(err, &cmds.SubCommandParseError{}) {
			log.Fatal(err)
		}
	}
}
