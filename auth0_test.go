package auth0

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

func genTestConfiguration(configuration Configuration, token string) (*JWTValidator, *http.Request) {
	validator := NewValidator(configuration, nil)

	req, _ := http.NewRequest("", "http://localhost", nil)
	authHeader := fmt.Sprintf("Bearer %s", token)
	req.Header.Add("Authorization", authHeader)

	return validator, req
}

func invalidProvider(req *http.Request) (interface{}, error) {
	return nil, errors.New("invalid secret provider")
}

func TestValidateRequestAndClaims(t *testing.T) {
	tests := []struct {
		name string
		// validator config
		configSecretProvider  SecretProvider
		configAud             []string
		configIss             string
		configAlg             jose.SignatureAlgorithm
		configNoEnforceSigAlg bool
		expectedErrorMsg      string
		// token attr
		tokenAud     []string
		tokenIss     string
		tokenExpTime time.Time
		tokenAlg     jose.SignatureAlgorithm
		tokenSecret  interface{}
	}{
		{
			name:                 "pass - token HS256",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "",
		},
		{
			name:                 "pass - token ES384",
			configSecretProvider: defaultSecretProviderES384,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.ES384,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.ES384,
			tokenSecret:          defaultSecretES384,
			expectedErrorMsg:     "",
		},
		{
			name:                 "pass - token, config empty iss, aud",
			configSecretProvider: defaultSecretProvider,
			configAud:            emptyAudience,
			configIss:            emptyIssuer,
			configAlg:            jose.HS256,
			tokenAud:             emptyAudience,
			tokenIss:             emptyIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "",
		},
		{
			name:                  "pass - token HS256 config no enforce sig alg",
			configSecretProvider:  defaultSecretProvider,
			configAud:             defaultAudience,
			configIss:             defaultIssuer,
			configNoEnforceSigAlg: true,
			tokenAud:              defaultAudience,
			tokenIss:              defaultIssuer,
			tokenExpTime:          time.Now().Add(24 * time.Hour),
			tokenAlg:              jose.HS256,
			tokenSecret:           defaultSecret,
			expectedErrorMsg:      "",
		},
		{
			name:                  "pass - token ES384 config no enforce sig alg",
			configSecretProvider:  defaultSecretProviderES384,
			configAud:             defaultAudience,
			configIss:             defaultIssuer,
			configNoEnforceSigAlg: true,
			tokenAud:              defaultAudience,
			tokenIss:              defaultIssuer,
			tokenExpTime:          time.Now().Add(24 * time.Hour),
			tokenAlg:              jose.ES384,
			tokenSecret:           defaultSecretES384,
			expectedErrorMsg:      "",
		},
		{
			name:                  "fail - config no enforce sig alg but invalid token alg",
			configSecretProvider:  defaultSecretProviderES384,
			configAud:             defaultAudience,
			configIss:             defaultIssuer,
			configNoEnforceSigAlg: true,
			tokenAud:              defaultAudience,
			tokenIss:              defaultIssuer,
			tokenExpTime:          time.Now().Add(24 * time.Hour),
			tokenAlg:              jose.RS256,
			tokenSecret:           defaultSecretRS256,
			expectedErrorMsg:      "error in cryptographic primitive",
		},
		{
			name:                 "fail - invalid config secret provider",
			configSecretProvider: SecretProviderFunc(invalidProvider),
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "invalid secret provider",
		},
		{
			name:                 "fail - invalid token aud",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             []string{"invalid aud"},
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "invalid audience claim (aud)",
		},
		{
			name:                 "fail - invalid token iss",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             "invalid iss",
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "invalid issuer claim (iss)",
		},
		{
			name:                 "fail - invalid token expiry",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(-24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "token is expired (exp)",
		},
		{
			name:                 "fail - invalid token alg",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS384,
			tokenSecret:          defaultSecret,
			expectedErrorMsg:     "Algorithm is invalid",
		},
		{
			name:                 "fail - invalid token secret",
			configSecretProvider: defaultSecretProvider,
			configAud:            defaultAudience,
			configIss:            defaultIssuer,
			configAlg:            jose.HS256,
			tokenAud:             defaultAudience,
			tokenIss:             defaultIssuer,
			tokenExpTime:         time.Now().Add(24 * time.Hour),
			tokenAlg:             jose.HS256,
			tokenSecret:          []byte("invalid secret"),
			expectedErrorMsg:     "error in cryptographic primitive",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := getTestToken(
				test.tokenAud,
				test.tokenIss,
				test.tokenExpTime,
				test.tokenAlg,
				test.tokenSecret,
			)
			var configuration Configuration
			if test.configNoEnforceSigAlg == true {
				configuration = NewConfigurationNoEnforceSigAlg(
					test.configSecretProvider,
					test.configAud,
					test.configIss,
				)
			} else {
				configuration = NewConfiguration(
					test.configSecretProvider,
					test.configAud,
					test.configIss,
					test.configAlg,
				)
			}

			validator, req := genTestConfiguration(configuration, token)

			jwt, err := validator.ValidateRequest(req)

			if test.expectedErrorMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedErrorMsg)

			} else {
				assert.NoError(t, err)

				// claims should be unmarshalled successfully
				claims := map[string]interface{}{}
				err = validator.Claims(req, jwt, &claims)
				assert.NoError(t, err)
			}
		})
	}
}
