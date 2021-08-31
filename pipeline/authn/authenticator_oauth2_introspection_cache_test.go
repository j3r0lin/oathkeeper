package authn

import (
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/viper"
	"github.com/ory/x/logrusx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache(t *testing.T) {
	viper.Reset()

	viper.Set("authenticators.oauth2_introspection.config.cache.enabled", true)
	viper.Set("authenticators.oauth2_introspection.config.introspection_url", "http://localhost:8080/")

	logger := logrusx.New("", "")
	c := configuration.NewViperProvider(logger)
	a := NewAuthenticatorOAuth2Introspection(c, logger)
	assert.Equal(t, "oauth2_introspection", a.GetID())

	config, _, err := a.Config(nil)
	require.NoError(t, err)

	t.Run("method=tokenToCache", func(t *testing.T) {
		t.Run("case=cache value", func(t *testing.T) {
			i := &AuthenticatorOAuth2IntrospectionResult{
				Active: true,
				Extra:  map[string]interface{}{"extra": "foo"},
			}

			a.tokenToCache(config, i, "token", fosite.WildcardScopeStrategy)
			// wait cache to save value
			time.Sleep(time.Millisecond * 100)

			// modify struct should not affect cached value
			i.Active = false
			v := a.tokenFromCache(config, "token", fosite.WildcardScopeStrategy)
			require.NotNil(t, v)
			require.True(t, v.Active)
		})

		t.Run("case=value cannot be marshaled to json should not be cached", func(t *testing.T) {
			i := &AuthenticatorOAuth2IntrospectionResult{
				Active: false,
				Extra:  map[string]interface{}{"extra": make(chan bool, 1)},
			}

			a.tokenToCache(config, i, "invalid-token", fosite.WildcardScopeStrategy)
			// wait cache to save value
			time.Sleep(time.Millisecond * 100)

			v := a.tokenFromCache(config, "invalid-token", fosite.WildcardScopeStrategy)
			require.Nil(t, v)
		})

		t.Run("case=cached invalid json value should not working", func(t *testing.T) {
			ok := a.tokenCache.Set("invalid-json", []byte("invalid-json-string"), 1)
			require.True(t, ok)
			// wait cache to save value
			time.Sleep(time.Millisecond * 100)

			v := a.tokenFromCache(config, "invalid-json", fosite.WildcardScopeStrategy)
			require.Nil(t, v)
		})

		t.Run("case=cache with ttl", func(t *testing.T) {
			i := &AuthenticatorOAuth2IntrospectionResult{
				Active: true,
			}

			config, _, _ := a.Config([]byte(`{ "cache": { "ttl": "1s" } }`))
			a.tokenToCache(config, i, "token", fosite.WildcardScopeStrategy)
			// wait cache to save value
			time.Sleep(time.Millisecond * 100)

			v := a.tokenFromCache(config, "token", fosite.WildcardScopeStrategy)
			require.NotNil(t, v)

			// wait cache to be expired
			time.Sleep(time.Second)
			v = a.tokenFromCache(config, "token", fosite.WildcardScopeStrategy)
			require.Nil(t, v)
		})
	})

}
