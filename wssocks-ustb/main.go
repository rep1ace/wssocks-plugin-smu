package main

import (
	"errors"
	"flag"
	"github.com/genshen/cmds"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/ver"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	"github.com/genshen/wssocks/client"
	_ "github.com/genshen/wssocks/cmd/client"
	_ "github.com/genshen/wssocks/cmd/server"
	log "github.com/sirupsen/logrus"
	//_ "github.com/genshen/wssocks/version"
	_ "github.com/rep1ace/wssocks-plugin-smu/wssocks-ustb/version"
)

// initialize USTB vpn (n.ustb.edu.cn) plugin
func init() {
	vpn := vpn.NewUstbVpnCli()
	ver := ver.PluginVersionNeg{}
	client.AddPluginOption(vpn)
	client.AddPluginRequest(vpn)
	client.AddPluginVersion(&ver)
}

func main() {
	cmds.SetProgramName("wssocks-ustb")
	if err := cmds.Parse(); err != nil {
		if !errors.Is(err, flag.ErrHelp) && !errors.Is(err, &cmds.SubCommandParseError{}) {
			log.Fatal(err)
		}
	}
}
