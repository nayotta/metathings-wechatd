package cmd

import (
	"strings"

	"github.com/nayotta/viper"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	cmd_helper "github.com/nayotta/metathings/pkg/common/cmd"
)

const (
	METATHINGS_WECHATD_PREFIX = "mtwcd"
)

type _rootOptions struct {
	cmd_helper.RootOptions `mapstructure:",squash"`
}

var (
	root_opts *_rootOptions
)

var (
	RootCmd = &cobra.Command{
		Use:   "metathings-wechatd",
		Short: "Metathings WeChat Adaptor Service",
	}
)

func initConfig() {
	if root_opts.Config != "" {
		viper.SetConfigFile(root_opts.Config)
		if err := viper.ReadInConfig(); err != nil {
			log.WithError(err).Fatalf("failed to read config")
		}
	}
}

func init() {
	root_opts = &_rootOptions{}

	cobra.OnInitialize(initConfig)
	viper.AutomaticEnv()
	viper.SetEnvPrefix(METATHINGS_WECHATD_PREFIX)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.BindEnv("stage")

	RootCmd.PersistentFlags().StringVarP(&root_opts.Config, "config", "c", "", "Config file")
	RootCmd.PersistentFlags().BoolVar(&root_opts.Verbose, "verbose", false, "Verbose mode")
	RootCmd.PersistentFlags().StringVar(&root_opts.Log.Level, "log-level", "info", "Logging Level[debug, info, warn, error]")
}
