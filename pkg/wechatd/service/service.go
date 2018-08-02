package metathings_wechatd_service

import (
	"context"
	"encoding/json"

	"github.com/cbroglie/mustache"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	gpb "github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/nayotta/metathings-wechatd/pkg/proto/wechatd"
	storage "github.com/nayotta/metathings-wechatd/pkg/wechatd/storage"
	app_cred_mgr "github.com/nayotta/metathings/pkg/common/application_credential_manager"
	client_helper "github.com/nayotta/metathings/pkg/common/client"
	context_helper "github.com/nayotta/metathings/pkg/common/context"
	grpc_helper "github.com/nayotta/metathings/pkg/common/grpc"
	log_helper "github.com/nayotta/metathings/pkg/common/log"
	identityd_pb "github.com/nayotta/metathings/pkg/proto/identityd"
)

type options struct {
	logLevel                       string
	metathingsd_addr               string
	identityd_addr                 string
	application_credential_id      string
	application_credential_secret  string
	domain_id                      string
	project_id                     string
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

func SetDomainId(id string) ServiceOptions {
	return func(o *options) {
		o.domain_id = id
	}
}

func SetProjectId(id string) ServiceOptions {
	return func(o *options) {
		o.project_id = id
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

func (self *metathingsWechatdService) GetMetathingsToken(ctx context.Context, req *pb.GetMetathingsTokenRequest) (*pb.GetMetathingsTokenResponse, error) {
	err := req.Validate()
	if err != nil {
		self.logger.WithError(err).Errorf("failed to validate request data")
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	openid := req.GetOpenId().GetValue()
	tkns, err := self.storage.GetTokensByOpenid(openid)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to get tokens by openid from storage")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	if len(tkns) == 0 {
		self.issueTokenByOpenid(ctx, openid)
		tkns, err = self.storage.GetTokensByOpenid(openid)
		if err != nil {
			self.logger.WithError(err).Errorf("failed to get tokens by openid from storage")
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		if len(tkns) == 0 {
			self.logger.WithField("openid", openid).Errorf("failed to issue token with openpid")
			return nil, status.Errorf(codes.Internal, ErrIssueToken.Error())
		}
	}
	res := &pb.GetMetathingsTokenResponse{
		Token: *tkns[0].Text,
	}

	self.logger.WithField("openid", openid).Infof("get metathings token")

	return res, nil
}

func (self *metathingsWechatdService) createUserAndApplicationCredential(cli identityd_pb.IdentitydServiceClient, ctx context.Context, openid string) (storage.ApplicationCredential, error) {
	username := random_username()
	password := random_password()

	// Create User
	create_user_req := &identityd_pb.CreateUserRequest{
		Name:             &gpb.StringValue{Value: username},
		Password:         &gpb.StringValue{Value: password},
		DomainId:         &gpb.StringValue{Value: self.opts.domain_id},
		DefaultProjectId: &gpb.StringValue{Value: self.opts.project_id},
		Enabled:          &gpb.BoolValue{Value: true},
	}

	_, err := cli.CreateUser(ctx, create_user_req)
	if err != nil {
		return storage.ApplicationCredential{}, err
	}
	self.logger.WithFields(log.Fields{"openid": openid, "username": username}).Infof("create user in identityd")

	// Issue Token
	var header metadata.MD
	issue_token_req := &identityd_pb.IssueTokenRequest{
		Method: identityd_pb.AUTH_METHOD_PASSWORD,
		Payload: &identityd_pb.IssueTokenRequest_Password{
			Password: &identityd_pb.PasswordPayload{
				Password: &gpb.StringValue{Value: password},
				Username: &gpb.StringValue{Value: username},
				DomainId: &gpb.StringValue{Value: self.opts.domain_id},
				Scope: &identityd_pb.TokenScope{
					DomainId:  &gpb.StringValue{Value: self.opts.domain_id},
					ProjectId: &gpb.StringValue{Value: self.opts.project_id},
				},
			},
		},
	}

	issue_token_res, err := cli.IssueToken(ctx, issue_token_req, grpc.Header(&header))
	if err != nil {
		return storage.ApplicationCredential{}, err
	}
	token_str := header["authorization"][0]
	self.logger.WithFields(log.Fields{"openid": openid, "username": username, "token": token_str}).Debugf("issue token in identityd")

	// Create Appliction Credential
	token := issue_token_res.Token
	user_id := token.User.Id
	tkn_ctx := context_helper.WithToken(ctx, token_str)
	create_application_credential_req := &identityd_pb.CreateApplicationCredentialRequest{
		UserId: &gpb.StringValue{Value: user_id},
		Name:   &gpb.StringValue{Value: "wechat"},
	}
	create_application_credential_res, err := cli.CreateApplicationCredential(tkn_ctx, create_application_credential_req)
	if err != nil {
		return storage.ApplicationCredential{}, err
	}

	app_cred_id := create_application_credential_res.ApplicationCredential.Id
	app_cred_secret := create_application_credential_res.ApplicationCredential.Secret
	self.logger.WithFields(log.Fields{"openid": openid, "app_cred_id": app_cred_id}).Infof("create application credential in identityd")

	app_cred, err := self.storage.CreateApplicationCredential(storage.ApplicationCredential{
		ApplicationCredentialId:     &app_cred_id,
		ApplicationCredentialSecret: &app_cred_secret,
		Openid: &openid,
	})

	return app_cred, nil
}

func (self *metathingsWechatdService) issueToken(cli identityd_pb.IdentitydServiceClient, ctx context.Context, app_cred_id, app_cred_secret string) (string, error) {
	var header metadata.MD
	req := &identityd_pb.IssueTokenRequest{
		Method: identityd_pb.AUTH_METHOD_APPLICATION_CREDENTIAL,
		Payload: &identityd_pb.IssueTokenRequest_ApplicationCredential{
			&identityd_pb.ApplicationCredentialPayload{
				Id:     &gpb.StringValue{Value: app_cred_id},
				Secret: &gpb.StringValue{Value: app_cred_secret},
			},
		},
	}

	_, err := cli.IssueToken(context.Background(), req, grpc.Header(&header))
	if err != nil {
		return "", err
	}

	token_text := header["authorization"][0][3:len(header["authorization"][0])]

	return token_text, nil
}

func (self *metathingsWechatdService) issueTokenByOpenid(ctx context.Context, openid string) (storage.Token, error) {
	cli, cfn, err := self.cli_fty.NewIdentitydServiceClient()
	if err != nil {
		return storage.Token{}, err
	}
	defer cfn()

	app_cred, err := self.storage.GetApplicationCredentialByOpenid(openid)
	if err != nil {
		app_cred, err = self.createUserAndApplicationCredential(cli, context.Background(), openid)
		if err != nil {
			self.logger.WithError(err).Errorf("failed to create user and application credential")
			return storage.Token{}, err
		}
	}

	token_text, err := self.issueToken(cli, context.Background(), *app_cred.ApplicationCredentialId, *app_cred.ApplicationCredentialSecret)
	if err != nil {
		return storage.Token{}, err
	}

	tkn := storage.Token{
		Openid: &openid,
		Text:   &token_text,
	}
	tkn, err = self.storage.CreateToken(tkn)
	if err != nil {
		return storage.Token{}, err
	}

	self.logger.WithFields(log.Fields{"openid": openid, "token": token_text}).Debugf("issue token from identityd")

	return tkn, nil
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
