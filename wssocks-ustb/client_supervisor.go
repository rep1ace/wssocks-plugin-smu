package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/genshen/cmds"
	baseclient "github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks/cmd/client"
	"github.com/rep1ace/wssocks-plugin-smu/extra"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	log "github.com/sirupsen/logrus"
)

type supervisedClientCommand struct {
	cmd     *cmds.Command
	options extra.Options
}

func init() {
	if ok, cmd := cmds.Find(client.CommandNameClient); ok {
		cmd.Runner = &supervisedClientCommand{cmd: cmd}
	}
}

func (c *supervisedClientCommand) PreRun() error {
	remoteAddr := c.stringFlag("remote")
	if remoteAddr == "" {
		return errors.New("empty remote address")
	}

	remoteURL, err := url.Parse(remoteAddr)
	if err != nil {
		return err
	}

	httpEnabled := c.boolFlag("http")
	if httpEnabled {
		log.Info("http(s) proxy is enabled.")
	} else {
		log.Info("http(s) proxy is disabled.")
	}

	headers, err := c.websocketHeaders()
	if err != nil {
		return err
	}

	c.options = extra.Options{
		Options: baseclient.Options{
			LocalSocks5Addr: c.stringFlag("addr"),
			HttpEnabled:     httpEnabled,
			LocalHttpAddr:   c.stringFlag("http-addr"),
			RemoteUrl:       remoteURL,
			RemoteHeaders:   headers,
			ConnectionKey:   c.stringFlag("key"),
			SkipTLSVerify:   c.boolFlag("skip-tls-verify"),
		},
		UstbVpn: vpn.UstbVpn{
			Enable:      c.boolFlag("vpn-enable"),
			ForceLogout: c.boolFlag("vpn-force-logout"),
			HostEncrypt: c.boolFlag("vpn-host-encrypt"),
			TargetVpn:   c.stringFlag("vpn-host"),
			AuthMethod:  vpn.VpnAuthMethodPasswd,
			PasswdAuth: passwd.UstbVpnPasswdAuth{
				Username: c.stringFlag("vpn-username"),
				Password: c.stringFlag("vpn-password"),
			},
		},
		RemoteAddr: remoteAddr,
	}
	return nil
}

func (c *supervisedClientCommand) Run() error {
	log.WithField("remote", c.options.RemoteAddr).Info("starting supervised wssocks client")
	handles := new(extra.TaskHandles)
	if err := handles.StartWssocks(c.options); err != nil {
		return err
	}
	return handles.Wait()
}

func (c *supervisedClientCommand) stringFlag(name string) string {
	flag := c.cmd.FlagSet.Lookup(name)
	if flag == nil {
		return ""
	}
	return flag.Value.String()
}

func (c *supervisedClientCommand) boolFlag(name string) bool {
	return strings.EqualFold(c.stringFlag(name), "true")
}

func (c *supervisedClientCommand) websocketHeaders() (http.Header, error) {
	headers := make(http.Header)
	flag := c.cmd.FlagSet.Lookup("ws-header")
	if flag == nil {
		return headers, nil
	}

	value := reflect.ValueOf(flag.Value)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	if value.Kind() != reflect.Slice {
		return headers, nil
	}

	for i := 0; i < value.Len(); i++ {
		header := value.Index(i).String()
		index := strings.IndexByte(header, '=')
		if index == -1 || index+1 == len(header) {
			return nil, fmt.Errorf("bad http header in websocket request: %s", header)
		}
		headers.Add(header[:index], header[index+1:])
	}
	return headers, nil
}
