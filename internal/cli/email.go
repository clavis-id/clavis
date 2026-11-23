package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"clavisid.org/clavis/email"
	"clavisid.org/clavis/internal/config"
	"clavisid.org/clavis/internal/emailtmpl"
	"clavisid.org/clavis/internal/i18n"
)

// testEmailTimeout bounds the delivery of a test message.
const testEmailTimeout = time.Minute

func newEmailCommand(environ []string) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "email",
		Short: "Check email delivery",
		Long:  "Check the email section of the configuration.\n\n" + configHelp,
		Args:  cobra.NoArgs,
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to the YAML configuration file")

	var to, locale string
	test := &cobra.Command{
		Use:   "test",
		Short: "Send a test message",
		Long: "Send a test message with the configured email driver and wait for the result, which the\n" +
			"server never does: it sends email in the background (ADR 0024).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			cfg, logger, err := setup(ctx, config.LoadEmail, configPathOrEnv(configPath, environ), environ,
				cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			sender, err := cfg.Email.Sender(logger)
			switch {
			case err != nil:
				return err
			case sender == nil:
				return errors.New("email is disabled: set email.driver to smtp, or to console for development")
			}
			l, ok := i18n.ParseLocale(locale)
			if !ok {
				return fmt.Errorf("--locale %q: want one of %s", locale, supportedLocales())
			}
			catalogs, err := i18n.Load()
			if err != nil {
				return err
			}
			msg, err := emailtmpl.Render(ctx, to, emailtmpl.TestMessage(catalogs.Printer(l), cfg.Issuer))
			if err != nil {
				return fmt.Errorf("--to: %w", err)
			}
			ctx, cancel := context.WithTimeout(ctx, testEmailTimeout)
			defer cancel()
			if err := sender.Send(ctx, msg); err != nil {
				return fmt.Errorf("sending the test message: %w", err)
			}
			if _, ok := sender.(*email.Console); ok {
				return write(cmd.OutOrStdout(), "Wrote the test message to the log: the console driver sends nothing.\n")
			}
			return write(cmd.OutOrStdout(), fmt.Sprintf("Sent a test message to %s.\n", to))
		},
	}
	test.Flags().StringVar(&to, "to", "", "address to send the test message to (required)")
	_ = test.MarkFlagRequired("to")
	test.Flags().StringVar(&locale, "locale", string(i18n.Default), "language of the test message: "+supportedLocales())
	cmd.AddCommand(test)
	return cmd
}

// supportedLocales lists the supported locales for help and error messages.
func supportedLocales() string {
	var names []string
	for _, l := range i18n.Supported() {
		names = append(names, string(l))
	}
	return strings.Join(names, ", ")
}
