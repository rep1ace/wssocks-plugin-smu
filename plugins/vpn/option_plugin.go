package vpn

import "github.com/rep1ace/wssocks/client"

// implementation of interface OptionPlugin
func (v *UstbVpn) OnOptionSet(options client.Options) error {
	v.ConnOptions = options
	return nil
}
