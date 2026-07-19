package main

import (
	"encoding/json"
	"os"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/subscription"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var subscriptionMetaPath string

var commandSubscription = &cobra.Command{
	Use:   "subscription",
	Short: "Control built-in subscription runtime",
}

var commandSubscriptionStatus = &cobra.Command{
	Use:   "status",
	Short: "Show subscription status",
	Run: func(cmd *cobra.Command, args []string) {
		err := subscriptionStatus()
		if err != nil {
			log.Fatal(err)
		}
	},
}

var commandSubscriptionSwitch = &cobra.Command{
	Use:   "switch [tag]",
	Short: "Switch active subscription",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := subscriptionSwitch(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

var commandSubscriptionUpdate = &cobra.Command{
	Use:   "update [tag]",
	Short: "Update subscription cache",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		tag := ""
		if len(args) > 0 {
			tag = args[0]
		}
		err := subscriptionUpdate(tag)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandSubscription.PersistentFlags().StringVarP(&subscriptionMetaPath, "subscription", "s", "", "subscription meta file path")
	commandSubscription.AddCommand(commandSubscriptionStatus, commandSubscriptionSwitch, commandSubscriptionUpdate)
	mainCommand.AddCommand(commandSubscription)
}

func requireSubMeta() (string, error) {
	if subscriptionMetaPath == "" {
		return "", E.New("subscription meta path is required: use -s/--subscription")
	}
	return subscriptionMetaPath, nil
}

func subscriptionDial(req subscription.Request) (*subscription.Response, error) {
	metaPath, err := requireSubMeta()
	if err != nil {
		return nil, err
	}
	listen, err := subscription.ListenFromMeta(metaPath)
	if err != nil {
		return nil, err
	}
	return subscription.DialRequest(listen, req)
}

func subscriptionStatus() error {
	resp, err := subscriptionDial(subscription.Request{Method: "status"})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(resp.Status)
}

func subscriptionSwitch(tag string) error {
	resp, err := subscriptionDial(subscription.Request{Method: "switch", Tag: tag})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(resp.Status)
}

func subscriptionUpdate(tag string) error {
	resp, err := subscriptionDial(subscription.Request{Method: "update", Tag: tag})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(resp.Status)
}
