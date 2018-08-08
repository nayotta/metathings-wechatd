package cmd

import (
	"math/rand"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	pb "github.com/nayotta/metathings-wechatd/pkg/proto/wechatd"
	service "github.com/nayotta/metathings-wechatd/pkg/wechatd/service"
	cmd_helper "github.com/nayotta/metathings/pkg/common/cmd"
	constant_helper "github.com/nayotta/metathings/pkg/common/constant"
)

type _wechatConfig struct {
	Appid  string
	Secret string
}

type _serveOptions struct {
	_rootOptions  `mapstructure:",squash"`
	Listen        string
	Storage       cmd_helper.StorageOptions
	ServiceConfig cmd_helper.ServiceConfigOptions `mapstructure:"service_config"`
	Wechat        _wechatConfig
	DomainId      string   `mapstructure:"domain_id"`
	ProjectId     string   `mapstructure:"project_id"`
	UserRoles     []string `mapstructure:"user_roles"`
	_userRoles    string   `mapstructure:"-"`
	TokenExpire   int      `mapstructure:"token_expire"`
}

var (
	serve_opts *_serveOptions
)

var (
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Metathings Wechat Service Daemon",
		PreRun: cmd_helper.DefaultPreRunHooks(func() {
			if root_opts.Config == "" {
				return
			}

			var opts _serveOptions
			cmd_helper.UnmarshalConfig(&opts)

			if serve_opts.ProjectId != "" {
				opts.ProjectId = serve_opts.ProjectId
			}

			if serve_opts.DomainId != "" {
				opts.DomainId = serve_opts.DomainId
			}

			if serve_opts.Wechat.Appid != "" {
				opts.Wechat.Appid = serve_opts.Wechat.Appid
			}

			if serve_opts.Wechat.Secret != "" {
				opts.Wechat.Secret = serve_opts.Wechat.Secret
			}

			if opts.TokenExpire == 0 {
				opts.TokenExpire = serve_opts.TokenExpire
			}

			if serve_opts._userRoles != "" {
				opts.UserRoles = []string{}
				for _, s := range strings.Split(serve_opts._userRoles, ",") {
					opts.UserRoles = append(opts.UserRoles, strings.TrimSpace(s))
				}
			}

			serve_opts = &opts
			root_opts = &serve_opts._rootOptions
			serve_opts.Stage = cmd_helper.GetStageFromEnv()
		}),
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(); err != nil {
				log.WithError(err).Fatalf("faield to serve")
			}
		},
	}
)

func serve() error {
	lis, err := net.Listen("tcp", serve_opts.Listen)
	if err != nil {
		return err
	}

	s := grpc.NewServer()
	srv, err := service.NewWechatdService(
		service.SetLogLevel(serve_opts.Log.Level),
		service.SetMetathingsdAddr(serve_opts.ServiceConfig.Metathingsd.Address),
		service.SetIdentitydAddr(serve_opts.ServiceConfig.Identityd.Address),
		service.SetApplicationCredential(serve_opts.ApplicationCredential.Id, serve_opts.ApplicationCredential.Secret),
		service.SetStorage(serve_opts.Storage.Driver, serve_opts.Storage.Uri),
		service.SetWechat(serve_opts.Wechat.Appid, serve_opts.Wechat.Secret),
		service.SetDomainId(serve_opts.DomainId),
		service.SetProjectId(serve_opts.ProjectId),
		service.SetUserRoles(serve_opts.UserRoles),
		service.SetTokenExpire(time.Duration(serve_opts.TokenExpire)*time.Second),
	)
	if err != nil {
		log.WithError(err).Errorf("failed to new wechat service")
		return err
	}

	pb.RegisterWechatdServiceServer(s, srv)

	log.WithField("listen", serve_opts.Listen).Infof("metathings wechatd service listening")
	return s.Serve(lis)
}

func init() {
	rand.Seed(int64(time.Now().Second()))

	serve_opts = &_serveOptions{}

	serveCmd.Flags().StringVarP(&serve_opts.Listen, "listen", "l", "127.0.0.1:5100", "Metathings Wechat Adaptor Service listening address")
	serveCmd.Flags().StringVar(&serve_opts.ServiceConfig.Metathingsd.Address, "metathingsd-addr", constant_helper.CONSTANT_METATHINGSD_DEFAULT_HOST, "Metathings Service Address")
	serveCmd.Flags().StringVar(&serve_opts.ServiceConfig.Identityd.Address, "identityd-addr", constant_helper.CONSTANT_METATHINGSD_DEFAULT_HOST, "Metathings Identity Service Address")

	serveCmd.Flags().StringVar(&serve_opts.ApplicationCredential.Id, "application-credential-id", "", "Metathings Wechat Adaptor Service Application Credential ID")
	serveCmd.Flags().StringVar(&serve_opts.ApplicationCredential.Secret, "application-credential-secret", "", "Metathings Wetchat Adaptor Service Application Credential Secret")
	serveCmd.Flags().StringVar(&serve_opts.Wechat.Appid, "wechat-appid", "", "Wechat AppID")
	serveCmd.Flags().StringVar(&serve_opts.Wechat.Secret, "wechat-secret", "", "Wechat AppSecret")
	serveCmd.Flags().StringVar(&serve_opts.DomainId, "domain-id", "", "Created user beyond to which domain")
	serveCmd.Flags().StringVar(&serve_opts.ProjectId, "project-id", "", "Created user beyond to which project")
	serveCmd.Flags().StringVar(&serve_opts._userRoles, "user-roles", "", "Assign which roles to user")
	serveCmd.Flags().IntVar(&serve_opts.TokenExpire, "token-expire", 45*60, "Metathings Token Expire Time [2700s]")

	RootCmd.AddCommand(serveCmd)
}
