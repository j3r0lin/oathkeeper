package authn

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/ory/x/logrusx"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/go-convenience/stringsx"

	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/helper"
	"github.com/ory/oathkeeper/pipeline"
)

func init() {
	gjson.AddModifier("this", func(json, arg string) string {
		return json
	})
}

type AuthenticatorBearerTokenFilter struct {
}

type AuthenticatorBearerTokenConfiguration struct {
	CheckSessionURL     string                      `json:"check_session_url"`
	BearerTokenLocation *helper.BearerTokenLocation `json:"token_from"`
	PreservePath        bool                        `json:"preserve_path"`
	PreserveHost        bool                        `json:"preserve_host"`
	ExtraFrom           string                      `json:"extra_from"`
	SubjectFrom         string                      `json:"subject_from"`
	SetHeaders          map[string]string           `json:"additional_headers"`
}

type AuthenticatorBearerToken struct {
	c        configuration.Provider
	cache    *ristretto.Cache
	logger   *logrusx.Logger
	cacheTTL time.Duration
}

func NewAuthenticatorBearerToken(c configuration.Provider, logger *logrusx.Logger) *AuthenticatorBearerToken {
	return &AuthenticatorBearerToken{
		c:        c,
		logger:   logger,
		cacheTTL: time.Second * 10,
	}
}

func (a *AuthenticatorBearerToken) GetID() string {
	return "bearer_token"
}

func (a *AuthenticatorBearerToken) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorBearerToken) Config(config json.RawMessage) (*AuthenticatorBearerTokenConfiguration, error) {
	var c AuthenticatorBearerTokenConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	if len(c.ExtraFrom) == 0 {
		c.ExtraFrom = "extra"
	}

	if len(c.SubjectFrom) == 0 {
		c.SubjectFrom = "sub"
	}

	if a.cache == nil {
		cost := int64(100000000)
		a.logger.Debugf("Creating bearer token cache with max cost: %d", cost)
		cache, err := ristretto.NewCache(&ristretto.Config{
			// This will hold about 1000 unique mutation responses.
			NumCounters: 10000,
			// Allocate a max
			MaxCost: cost,
			// This is a best-practice value.
			BufferItems: 64,
		})
		if err != nil {
			return nil, err
		}

		a.cache = cache
	}

	return &c, nil
}

func (a *AuthenticatorBearerToken) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) error {
	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	token := helper.BearerTokenFromRequest(r, cf.BearerTokenLocation)
	if token == "" {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	cached := true
	body := a.tokenFromCache(token)
	if body == nil {
		body, err = forwardRequestToSessionStore(r, cf.CheckSessionURL, cf.PreservePath, cf.PreserveHost, cf.SetHeaders)
		if err != nil {
			return err
		}
		cached = true
	}

	var (
		subject string
		extra   map[string]interface{}

		subjectRaw = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.SubjectFrom).Raw, "null"))
		extraRaw   = []byte(stringsx.Coalesce(gjson.GetBytes(body, cf.ExtraFrom).Raw, "null"))
	)

	if err = json.Unmarshal(subjectRaw, &subject); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured subject_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.SubjectFrom, body, subjectRaw).WithTrace(err)
	}

	if err = json.Unmarshal(extraRaw, &extra); err != nil {
		return helper.ErrForbidden.WithReasonf("The configured extra_from GJSON path returned an error on JSON output: %s", err.Error()).WithDebugf("GJSON path: %s\nBody: %s\nResult: %s", cf.ExtraFrom, body, extraRaw).WithTrace(err)
	}

	session.Subject = subject
	session.Extra = extra

	if !cached {
		a.cache.SetWithTTL(token, body, 1, a.cacheTTL)
	}
	return nil
}

func (a *AuthenticatorBearerToken) tokenFromCache(token string) json.RawMessage {
	if item, found := a.cache.Get(token); found {
		return item.(json.RawMessage)
	}

	return nil
}
