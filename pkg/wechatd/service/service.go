package metathings_wechatd_service

import (
	"context"
	"encoding/json"

	"github.com/cbroglie/mustache"
	"github.com/jinzhu/gorm"
	"github.com/parnurzeal/gorequest"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	gpb "github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/nayotta/metathings-wechatd/pkg/proto/wechatd"
	storage "github.com/nayotta/metathings-wechatd/pkg/wechatd/storage"
	"github.com/nayotta/metathings/pkg/common"
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
	user_roles                     map[string]string
	storage_driver                 string
	storage_uri                    string
	wechat_appid                   string
	wechat_secret                  string
	wechat_jscode2session_template string
}

var defaultServiceOptions = options{
	logLevel:                       "info",
	wechat_jscode2session_template: "https://api.weixin.qq.com/sns/jscode2session?appid={{appid}}&secret={{secret}}&js_code={{jscode}}&grant_type=authorization_code",
	user_roles:                     map[string]string{},
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

func SetUserRoles(roles []string) ServiceOptions {
	return func(o *options) {
		for _, role := range roles {
			o.user_roles[role] = ""
		}
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
		Errcode    int
		Errmsg     string
	}

	err = json.Unmarshal([]byte(http_body), &sess)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to unmarshal http body to json")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	if sess.Errcode != 0 {
		self.logger.WithFields(log.Fields{"errcode": sess.Errcode, "errmsg": sess.Errmsg}).Errorf("failed to get session from tencent wechat service")
		return nil, status.Errorf(codes.Internal, sess.Errmsg)
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
		app_cred, err := self.storage.GetApplicationCredential(openid)
		if err != nil {
			if err == gorm.ErrRecordNotFound {
				self.logger.WithField("openid", openid).Debugf("openid not registered")
				return &pb.GetMetathingsTokenResponse{}, nil
			}
		}

		_, err = self.issueToken(ctx, openid, app_cred)
		if err != nil {
			self.logger.WithError(err).Errorf("failed to issue token by openid")
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		tkns, err = self.storage.GetTokensByOpenid(openid)
		if err != nil {
			self.logger.WithError(err).Errorf("failed to get tokens by openid from storage")
			return nil, status.Errorf(codes.Internal, err.Error())
		}

		if len(tkns) == 0 {
			self.logger.WithField("openid", openid).Errorf("failed to issue token with openid")
			return nil, status.Errorf(codes.Internal, ErrIssueToken.Error())
		}

		self.logger.WithField("openid", openid).Infof("issue token")
	}

	res := &pb.GetMetathingsTokenResponse{
		Openid: openid,
		Token:  *tkns[0].Text,
	}
	self.logger.WithField("openid", openid).Debugf("get metathings token")

	return res, nil
}

func (self *metathingsWechatdService) createUserAndApplicationCredential(cli identityd_pb.IdentitydServiceClient, ctx context.Context, openid string) (storage.ApplicationCredential, error) {
	username := random_username()
	password := random_password()

	// Create User
	wechatd_ctx := context_helper.WithToken(context.Background(), self.app_cred_mgr.GetToken())
	create_user_req := &identityd_pb.CreateUserRequest{
		Name:             &gpb.StringValue{Value: username},
		Password:         &gpb.StringValue{Value: password},
		DomainId:         &gpb.StringValue{Value: self.opts.domain_id},
		DefaultProjectId: &gpb.StringValue{Value: self.opts.project_id},
		Enabled:          &gpb.BoolValue{Value: true},
	}

	create_user_res, err := cli.CreateUser(wechatd_ctx, create_user_req)
	if err != nil {
		return storage.ApplicationCredential{}, err
	}
	self.logger.WithFields(log.Fields{"openid": openid, "username": username}).Debugf("create user in identityd")

	// Assign Roles To User
	user_id := create_user_res.User.Id
	for role, role_id := range self.opts.user_roles {
		add_role_to_user_on_project_req := &identityd_pb.AddRoleToUserOnProjectRequest{
			UserId:    &gpb.StringValue{Value: user_id},
			ProjectId: &gpb.StringValue{Value: self.opts.project_id},
			RoleId:    &gpb.StringValue{Value: role_id},
		}
		_, err = cli.AddRoleToUserOnProject(wechatd_ctx, add_role_to_user_on_project_req)
		if err != nil {
			return storage.ApplicationCredential{}, err
		}
		self.logger.WithFields(log.Fields{"openid": openid, "user_id": user_id, "role": role}).Debugf("assign role to user in identityd")
	}

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
					ProjectId: &gpb.StringValue{Value: self.opts.project_id},
				},
			},
		},
	}

	_, err = cli.IssueToken(ctx, issue_token_req, grpc.Header(&header))
	if err != nil {
		return storage.ApplicationCredential{}, err
	}
	token_str := header["authorization"][0]
	self.logger.WithFields(log.Fields{"openid": openid, "username": username, "token": token_str}).Debugf("issue token in identityd")

	// Create Appliction Credential
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
	self.logger.WithFields(log.Fields{"openid": openid, "app_cred_id": app_cred_id}).Debugf("create application credential in identityd")

	app_cred, err := self.storage.CreateApplicationCredential(storage.ApplicationCredential{
		ApplicationCredentialId:     &app_cred_id,
		ApplicationCredentialSecret: &app_cred_secret,
		Openid: &openid,
	})

	return app_cred, nil
}

func (self *metathingsWechatdService) issueToken(ctx context.Context, openid string, app_cred storage.ApplicationCredential) (storage.Token, error) {
	cli, cfn, err := self.cli_fty.NewIdentitydServiceClient()
	if err != nil {
		return storage.Token{}, err
	}
	defer cfn()

	var header metadata.MD
	req := &identityd_pb.IssueTokenRequest{
		Method: identityd_pb.AUTH_METHOD_APPLICATION_CREDENTIAL,
		Payload: &identityd_pb.IssueTokenRequest_ApplicationCredential{
			&identityd_pb.ApplicationCredentialPayload{
				Id:     &gpb.StringValue{Value: *app_cred.ApplicationCredentialId},
				Secret: &gpb.StringValue{Value: *app_cred.ApplicationCredentialSecret},
			},
		},
	}

	_, err = cli.IssueToken(context.Background(), req, grpc.Header(&header))
	if err != nil {
		self.logger.WithError(err).Errorf("failed to issue token from identityd")
		return storage.Token{}, err
	}

	token_text := header["authorization"][0][3:len(header["authorization"][0])]

	tkn_id := common.NewId()
	tkn := storage.Token{
		Id:     &tkn_id,
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

func (self *metathingsWechatdService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	err := req.Validate()
	if err != nil {
		self.logger.WithError(err).Errorf("failed to validate request data")
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	openid := req.GetOpenid().GetValue()
	username_str := random_username()
	username := req.GetUsername()
	if username != nil {
		username_str = username.GetValue()
	}
	password_str := random_password()
	password := req.GetPassword()
	if password != nil {
		password_str = password.GetValue()
	}

	wechatd_ctx := context_helper.WithToken(context.Background(), self.app_cred_mgr.GetToken())
	create_user_req := &identityd_pb.CreateUserRequest{
		Name:             &gpb.StringValue{Value: username_str},
		Password:         &gpb.StringValue{Value: password_str},
		DomainId:         &gpb.StringValue{Value: self.opts.domain_id},
		DefaultProjectId: &gpb.StringValue{Value: self.opts.project_id},
		Enabled:          &gpb.BoolValue{Value: true},
		Extra:            map[string]string{},
	}

	for key, val := range req.Extra {
		create_user_req.Extra[key] = val
	}

	cli, cfn, err := self.cli_fty.NewIdentitydServiceClient()
	if err != nil {
		self.logger.WithError(err).Errorf("failed to create identity service client")
		return nil, status.Errorf(codes.Internal, err.Error())
	}
	defer cfn()

	create_user_res, err := cli.CreateUser(wechatd_ctx, create_user_req)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to create user in identityd")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	_, err = self.storage.CreateApplicationCredential(storage.ApplicationCredential{
		Openid: &openid,
	})

	if err != nil {
		self.logger.WithError(err).Errorf("failed to create application credential placeholder")
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	go self.post_create_user(create_user_res.User.Id, username_str, password_str, openid)

	res := &pb.CreateUserResponse{
		User: &pb.User{
			Id:       create_user_res.User.Id,
			Username: username_str,
			Extra:    req.Extra,
		},
	}

	self.logger.WithFields(log.Fields{
		"openid":   openid,
		"username": username_str,
		"user_id":  create_user_res.User.Id,
	}).Infof("create user")

	return res, nil
}

func (self *metathingsWechatdService) post_create_user(user_id, username, password, openid string) {
	cli, cfn, err := self.cli_fty.NewIdentitydServiceClient()
	if err != nil {
		self.logger.WithError(err).Errorf("failed to new identity service client")
		self.on_post_create_user_failed(user_id, username, password, openid)
		return
	}
	defer cfn()
	ctx := context.Background()
	wechatd_ctx := context_helper.WithToken(ctx, self.app_cred_mgr.GetToken())

	// Assign Roles To User
	for role, role_id := range self.opts.user_roles {
		add_role_to_user_on_project_req := &identityd_pb.AddRoleToUserOnProjectRequest{
			UserId:    &gpb.StringValue{Value: user_id},
			ProjectId: &gpb.StringValue{Value: self.opts.project_id},
			RoleId:    &gpb.StringValue{Value: role_id},
		}
		_, err = cli.AddRoleToUserOnProject(wechatd_ctx, add_role_to_user_on_project_req)
		if err != nil {
			self.logger.WithError(err).Errorf("failed to add role to user on project in identityd")
			self.on_post_create_user_failed(user_id, username, password, openid)
			return
		}
		self.logger.WithFields(log.Fields{"openid": openid, "user_id": user_id, "role": role}).Debugf("assign role to user in identityd")
	}

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
					ProjectId: &gpb.StringValue{Value: self.opts.project_id},
				},
			},
		},
	}

	_, err = cli.IssueToken(ctx, issue_token_req, grpc.Header(&header))
	if err != nil {
		self.logger.WithError(err).Errorf("failed to issue token from identityd")
		self.on_post_create_user_failed(user_id, username, password, openid)
		return
	}
	token_str := header["authorization"][0]
	self.logger.WithFields(log.Fields{"openid": openid, "username": username, "token": token_str}).Debugf("issue token in identityd")

	// Create Appliction Credential
	tkn_ctx := context_helper.WithToken(ctx, token_str)
	create_application_credential_req := &identityd_pb.CreateApplicationCredentialRequest{
		UserId: &gpb.StringValue{Value: user_id},
		Name:   &gpb.StringValue{Value: "wechat"},
	}
	create_application_credential_res, err := cli.CreateApplicationCredential(tkn_ctx, create_application_credential_req)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to create application credential in identityd")
		self.on_post_create_user_failed(user_id, username, password, openid)
		return
	}

	app_cred_id := create_application_credential_res.ApplicationCredential.Id
	app_cred_secret := create_application_credential_res.ApplicationCredential.Secret
	self.logger.WithFields(log.Fields{"openid": openid, "app_cred_id": app_cred_id}).Debugf("create application credential in identityd")

	_, err = self.storage.UpdateApplicationCredential(openid, storage.ApplicationCredential{
		ApplicationCredentialId:     &app_cred_id,
		ApplicationCredentialSecret: &app_cred_secret,
	})
	if err != nil {
		self.logger.WithError(err).Errorf("failed to update application credential in storage")
		self.on_post_create_user_failed(user_id, username, password, openid)
		return
	}

	self.logger.WithFields(log.Fields{"user_id": user_id, "username": username, "openid": openid}).Infof("create user finish")
}

func (self *metathingsWechatdService) on_post_create_user_failed(user_id, username, password, openid string) {
	err := self.storage.DeleteApplicationCredential(openid)
	if err != nil {
		self.logger.WithError(err).Errorf("failed to delete application credential by openid when post create user failed")
	}
}

func (self *metathingsWechatdService) initialize() error {
	cli, cfn, err := self.cli_fty.NewIdentitydServiceClient()
	if err != nil {
		return err
	}
	defer cfn()

	ctx := context_helper.WithToken(context.Background(), self.app_cred_mgr.GetToken())
	res, err := cli.ListRoles(ctx, &identityd_pb.ListRolesRequest{})
	if err != nil {
		return err
	}

	for _, role := range res.Roles {
		if _, ok := self.opts.user_roles[role.Name]; ok {
			self.opts.user_roles[role.Name] = role.Id
		}
	}

	self.logger.Debugf("wechat service initialized")

	return nil
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

	err = srv.initialize()
	if err != nil {
		log.WithError(err).Errorf("failed to initialize wechat service")
		return nil, err
	}

	logger.Debugf("new wechatd service")

	return srv, nil
}
