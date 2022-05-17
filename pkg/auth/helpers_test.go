package auth

import (
	"net/http"
)

var (
	jwtTokenValid    = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjBhZDk5ODY5ZjJkNGU1N2YzZjcxYzY4MzAwYmE4NGZhIn0.eyJleHAiOjE5ODEzOTgxMTF9.MHSHryNl0oU3ZBjWc0pFIBKlXHcXU0vcoO3PpRg8MIQ8M14k4sTsUqJfxXCTbxh24YKE6w0XFBh9B4L7vjIY7iVZPM44LXNEzUFyyX3m6eN_iAavGKPKdKnao2ayNeu1`
	jwtTokenExpired  = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjBhZDk5ODY5ZjJkNGU1N2YzZjcxYzY4MzAwYmE4NGZhIn0.eyJleHAiOjExODEzOTgxMTF9.Qbi7klMrWKSM2z89AtMyDk_lRYnxxz0WApEO5iPikEcAzemmJyR_7b1IvHVxR4uQgCZrH46anUD0aTtPG7k3PpMjP2o2pDHWgY0mWlxW0lDlMqkrvZtBPC7qa_NJTHFl`
	jwtTokenNotYet   = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjBhZDk5ODY5ZjJkNGU1N2YzZjcxYzY4MzAwYmE4NGZhIn0.eyJleHAiOjE5ODEzOTgxMTEsIm5iZiI6MTk4MTM5ODExMX0.imZHharGl5zu3pVcFdzpP78Zp_Quv4bOqA1v21uhgtTpAMjppHjgLZufCOmxyzNHawSfQRopMDI0jTMoXZtdmtJZldlsxJ--Yfl9o3Xj1ooaFNU5ipLsnSCJqkXpgL4i`
	unknownPublicKey = `{
		"crv": "P-384",
		"key_ops": [
		  "verify"
		],
		"kty": "EC",
		"x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX",
		"y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U",
		"alg": "ES384",
		"use": "sig",
		"kid": "32b3da5277b142c7e24fdf0ef09e0919"
	  }`
	publicKey = `{
		"crv": "P-384",
		"d": "FfTHqwIAM3OMj808FlAL59OkwdXnfmc8FAXtTqyKnfu023kXHtDrAjEwMEBnOC3O",
		"key_ops": [
		  "sign"
		],
		"kty": "EC",
		"x": "c9ZzWUHmgUpCiDMpxaIhPxORaFqMx_HB6DQUmFM0M1GFCdxoaZwAPv2KONgoaRxZ",
		"y": "zTt0paDnsE98Sd7erCVvLWLGGnGcjbOVy5C3m6AI116hUV5JeFAspBe_uDTnAfBD",
		"alg": "ES384",
		"use": "sig",
		"kid": "0ad99869f2d4e57f3f71c68300ba84fa"
	  }`
)

type mockClient struct {
	callback Do
}

func newTestClient(callback Do) *mockClient {
	return &mockClient{callback: callback}
}

func (c *mockClient) Do(r *http.Request) (*http.Response, error) {
	if c.callback == nil {
		return nil, nil
	}
	return c.callback(r)
}

type ConfigBuilder struct {
	conf *Config
}

func newTestConfig() *ConfigBuilder {
	return &ConfigBuilder{conf: &Config{ProjectID: "a"}}
}

func (cb *ConfigBuilder) WithInvalidKey() *ConfigBuilder {
	cb.conf.PublicKey = `{"test": "test"}`
	return cb
}

func (cb *ConfigBuilder) WithValidKey() *ConfigBuilder {
	cb.conf.PublicKey = publicKey
	return cb
}

func (cb *ConfigBuilder) WithProjectID(id string) *ConfigBuilder {
	cb.conf.ProjectID = id
	return cb
}

func (cb *ConfigBuilder) WithDefaultURL(url string) *ConfigBuilder {
	cb.conf.DefaultURL = url
	return cb
}

func (cb *ConfigBuilder) WithDebug() *ConfigBuilder {
	cb.conf.LogLevel = LogDebug
	return cb
}

func (cb *ConfigBuilder) WithDefaultClient(callback Do) *ConfigBuilder {
	cb.conf.DefaultClient = newTestClient(callback)
	return cb
}

func (cb *ConfigBuilder) WithCustomHeaders(headers map[string]string) *ConfigBuilder {
	cb.conf.CustomDefaultHeaders = headers
	return cb
}

func (cb *ConfigBuilder) WithUnkownKey() *ConfigBuilder {
	cb.conf.PublicKey = unknownPublicKey
	return cb
}

func (cb *ConfigBuilder) Build() *Config {
	return cb.conf
}
