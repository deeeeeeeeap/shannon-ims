package driver

import "go.uber.org/multierr"

type NetTxn struct {
	net   *NetTools
	undos []func() error
}

func (n *NetTools) Begin() *NetTxn {
	return &NetTxn{net: n}
}

func (tx *NetTxn) Commit() {
	tx.undos = nil
}

func (tx *NetTxn) Rollback() error {
	var err error
	for i := len(tx.undos) - 1; i >= 0; i-- {
		err = multierr.Append(err, tx.undos[i]())
	}
	tx.undos = nil
	return err
}

func (tx *NetTxn) SetLinkUp(iface string) error {
	if err := tx.net.SetLinkUp(iface); err != nil {
		return err
	}
	tx.undos = append(tx.undos, func() error {
		return tx.net.SetLinkDown(iface)
	})
	return nil
}

func (tx *NetTxn) SetMTU(iface string, mtu int) error {
	return tx.net.SetMTU(iface, mtu)
}

func (tx *NetTxn) AddAddress(iface string, cidr string) error {
	if err := tx.net.AddAddress(iface, cidr); err != nil {
		return err
	}
	tx.undos = append(tx.undos, func() error {
		return tx.net.DelAddress(iface, cidr)
	})
	return nil
}

func (tx *NetTxn) AddRoute(cidr string, gw string, iface string) error {
	if err := tx.net.AddRoute(cidr, gw, iface); err != nil {
		return err
	}
	tx.undos = append(tx.undos, func() error {
		return tx.net.DelRoute(cidr, gw, iface)
	})
	return nil
}

func (tx *NetTxn) AddAddress6(iface string, cidr string) error {
	if err := tx.net.AddAddress6(iface, cidr); err != nil {
		return err
	}
	tx.undos = append(tx.undos, func() error {
		return tx.net.DelAddress6(iface, cidr)
	})
	return nil
}

func (tx *NetTxn) AddRoute6(cidr string, gw string, iface string) error {
	if err := tx.net.AddRoute6(cidr, gw, iface); err != nil {
		return err
	}
	tx.undos = append(tx.undos, func() error {
		return tx.net.DelRoute6(cidr, gw, iface)
	})
	return nil
}
