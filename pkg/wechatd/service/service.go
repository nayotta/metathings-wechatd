package metathings_wechatd_service

import (
	"context"
	"encoding/json"

	"github.com/cbroglie/mustache"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nayotta/metathings-wechatd/pkg/proto/wechatd"
	storage "github.com/nayotta/metathings-wechatd/pkg/wechatd/storage"
	app_cred_mgr "github.com/nayotta/metathings/pkg/common/application_credential_manager"
	client_helper "github.com/nayotta/metathings/pkg/common/client"
	grpc_helper "github.com/nayotta/metathings/pkg/common/grpc"
	log_helper "github.com/nayotta/metathings/pkg/common/log"
)

type options struct {
	logLevel                       string
	metathingsd_addr               string
	identityd_addr                 string
	application_credential_id      string
	application_credential_secret  string
	storage_driver                 string
	storage_uri                    string
	wechat_appid                   string
	wechat_secret                  string
	wechat_jscode2session_template string
}

var defaultServiceOptions = options{
	logLevel:                       "info",
	wechat_jscode2session_template: "https://api.weixin.qq.com/sns/jscode2session?appid={APPID}&secret={SECRET}&js_code={JSCODE}&grant_type=authorization_code",
}

type ServiceOptions func(*options)

func SetLogLevel(lvl string) ServiceOptions {
	return func(o *options) {
		o.logLevel = lvl
	}
}

func SetMetathingsdAddr(addr string) ServiceOptions {
	return func(o *options) {
		o.metathingsd_addr = addr
	}
}

func SetIdentitydAddr(addr string) ServiceOptions {
	return func(o *options) {
		o.identityd_addr = addr
	}
}

func SetApplicationCredential(id, secret string) ServiceOptions {
	return func(o *options) {
		o.application_credential_id = id
		o.application_credential_secret = secret
	}
}

func SetStorage(driver, uri string) ServiceOptions {
	return func(o *options) {
		o.storage_driver = driver
		o.storage_uri = uri
	}
}

func SetWechat(appid, secret string) ServiceOptions {
	return func(o *options) {
		o.wechat_appid = appid
		o.wechat_secret = secret
	}
}

type metathingsWechatdService struct {
	cli_fty      *client_helper.ClientFactory
	app_cred_mgr app_cred_mgr.ApplicationCredentialManager
	logger       log.FieldLogger
	opts         options
	storage      storage.Storage
}

func (self *metathingsWechatdService) GetWechatSession(ctx context.Context, req *pb.GetWechatSessionRequest) (*pb.GetWechatSessionResponse, error) {
	err := req.Validate()
	if err != nil {
		self.logger.WithError(err).Errorf("failed to validate request data")
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	jscode := req.GetJsCode().GetValue()
	rdr_opts := map[string]interface{}{
		"appid":  self.opts.wechat_appid,
		"secret": self.opts.wechat_secret,
		"jscode": jscode,
	}
	url, err := mustache.Render(self.opts.wechat_jscode2session_template, rdr_opts)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to render jscode2openid url")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	http_res, http_body, errs := gorequest.New().Get(url).End()
	if len(errs) > 0 {
		return nil, status.Errorf(codes.Internal, errs[0].Error())
	}

	if http_res.StatusCode != 200 {
		self.logger.WithFields(log.Fields{
			"status_code": http_res.StatusCode,
			"http_body":   http_body,
		}).Errorf("unexpected status code")
		return nil, status.Errorf(grpc_helper.HttpStatusCode2GrpcStatusCode(http_res.StatusCode), http_body)
	}

	var sess struct {
		SessionKey string `json:"session_key"`
		Openid     string
	}

	err = json.Unmarshal([]byte(http_body), &sess)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to unmarshal http body to json")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	res := &pb.GetWechatSessionResponse{
		OpenId:     sess.Openid,
		SessionKey: sess.SessionKey,
	}

	self.logger.WithField("openid", sess.Openid).Debugf("get wechat session")

	return res, nil
}
func (self *metathingsWechatdService) GetMetathingsToken(context.Context, *pb.GetMetathingsTokenRequest) (*pb.GetMetathingsTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "unimplemented")
}

func NewWechatdService(opt ...ServiceOptions) (*metathingsWechatdService, error) {
	opts := defaultServiceOptions
	for _, o := range opt {
		o(&opts)
	}

	logger, err := log_helper.NewLogger("wechatd", opts.logLevel)
	if err != nil {
		return nil, err
	}

	cli_fty_cfgs := client_helper.NewDefaultServiceConfigs(opts.metathingsd_addr)
	cli_fty_cfgs[client_helper.IDENTITYD_CONFIG] = client_helper.ServiceConfig{Address: opts.identityd_addr}
	cli_fty, err := client_helper.NewClientFactory(
		cli_fty_cfgs,
		client_helper.WithInsecureOptionFunc(),
	)
	if err != nil {
		logger.WithError(err).Errorf("failed to new client factory")
		return nil, err
	}

	storage, err := storage.NewStorage(opts.storage_driver, opts.storage_uri, logger)
	if err != nil {
		logger.WithError(err).Errorf("failed to connect storage")
		return nil, err
	}

	app_cred_mgr, err := app_cred_mgr.NewApplicationCredentialManager(
		cli_fty,
		opts.application_credential_id,
		opts.application_credential_secret,
	)
	if err != nil {
		logger.WithError(err).Errorf("failed to new application credential manager")
		return nil, err
	}

	srv := &metathingsWechatdService{
		cli_fty:      cli_fty,
		app_cred_mgr: app_cred_mgr,
		opts:         opts,
		logger:       logger,
		storage:      storage,
	}

	logger.Debugf("new wechatd service")

	return srv, nil
}
