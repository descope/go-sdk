package descope

import (
	"fmt"
	"net/http"
	"strings"
)

var (
	// server common
	ErrBadRequest        = newServerError("E011001")
	ErrInvalidArguments  = newServerError("E011002")
	ErrValidationFailure = newServerError("E011003")
	ErrMissingArguments  = newServerError("E011004")

	// server authentication
	ErrUserAlreadyExists         = newServerError("E062107")
	ErrInvalidOneTimeCode        = newServerError("E061102")
	ErrEnchantedLinkUnauthorized = newServerError("E062503")

	// server management
	ErrManagementUserNotFound = newServerError("E112102")

	// server infra
	ErrRateLimitExceeded = newServerError("E130429")

	// client setup
	ErrMissingProjectID = newClientError("C010001", "Missing project ID")

	// client service error
	ErrUnexpectedResponse = newClientError("C020001", "Unexpected response")
	ErrInvalidResponse    = newClientError("C020002", "Invalid response")

	// client functional errors
	ErrPublicKey        = newClientError("C030001", "Missing or invalid public key")
	ErrInvalidToken     = newClientError("C030002", "Invalid token")
	ErrRefreshToken     = newClientError("C030003", "Missing or invalid refresh token")
	ErrInvalidStepUpJWT = newClientError("C030004", "Refresh token must be provided for stepup actions")
)

// Additional information that might be available in the
// Error struct's Info map for specific errors
var ErrorInfoKeys = errorInfoKeys{
	HTTPResponseStatusCode:      "Status-Code",
	RateLimitExceededRetryAfter: "Retry-After",
}

type Error struct {
	Code        string         `json:"errorCode,omitempty"`
	Description string         `json:"errorDescription,omitempty"`
	Message     string         `json:"errorMessage,omitempty"`
	Info        map[string]any `json:"-"`
}

func (e *Error) Error() string {
	str := fmt.Sprintf("[%s]", e.Code)
	if e.Description != "" && e.Message != "" {
		str = fmt.Sprintf("%s %s: %s", str, e.Description, e.Message)
	} else if e.Description != "" || e.Message != "" {
		str = fmt.Sprintf("%s %s%s", str, e.Description, e.Message)
	}
	if len(e.Info) > 0 {
		str = fmt.Sprintf("%s %s", str, strings.TrimPrefix(fmt.Sprintf("%v", e.Info), "map"))
	}
	return str
}

func (e *Error) Is(err error) bool {
	if de, ok := err.(*Error); ok {
		return e.Code == de.Code
	}
	return false
}

func (e Error) WithMessage(format string, args ...any) *Error {
	e.Message = fmt.Sprintf(format, args...)
	return &e
}

func (e Error) WithInfo(key string, value any) *Error {
	if e.Info == nil {
		e.Info = map[string]any{}
	}
	e.Info[key] = value
	return &e
}

func (e *Error) IsUnauthorized() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusUnauthorized
}

func (e *Error) IsNotFound() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusNotFound
}

func IsError(err error) bool {
	_, ok := err.(*Error)
	return ok
}

func IsUnauthorizedError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsUnauthorized()
	}
	return false
}

func IsNotFoundError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.IsNotFound()
	}
	return false
}

func newServerError(code string) *Error {
	return &Error{Code: code}
}

func newClientError(code, desc string) *Error {
	return &Error{Code: code, Description: desc}
}

type errorInfoKeys struct {
	HTTPResponseStatusCode      string
	RateLimitExceededRetryAfter string
}
