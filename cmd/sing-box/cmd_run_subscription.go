package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/subscription"
	E "github.com/sagernet/sing/common/exceptions"
)

// runSubscription 走 --subscription 入口: controller 外置, Box 可 teardown/rebuild.
func runSubscription(metaPath string) error {
	ctrl, err := subscription.NewController(globalCtx, metaPath, disableColor)
	if err != nil {
		return err
	}
	err = ctrl.Start()
	if err != nil {
		_ = ctrl.Close()
		return err
	}
	defer ctrl.Close()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(osSignals)

	for {
		select {
		case <-ctrl.Done():
			return E.New("subscription controller stopped")
		case osSignal := <-osSignals:
			if osSignal == syscall.SIGHUP {
				err = ctrl.ReloadMeta()
				if err != nil {
					log.Error(E.Cause(err, "reload subscription meta"))
				}
				continue
			}
			return nil
		}
	}
}
