package descope

import (
	"fmt"
)

var (
	// server common
	ErrBadRequest        = newServerError("E011001")
	ErrInvalidArguments  = newServerError("E011002")
	ErrValidationFailure = newServerError("E011003")
	ErrMissingArguments  = newServerError("E011004")

	// server authentication
	ErrEnchantedLinkUnauthorized = newServerError("E062503")

	// server management
	ErrManagementUserNotFound = newServerError("E112102")

	// client setup
	ErrMissingProjectID = newClientError("C010001", "Missing project ID")

	// client service error
	ErrInvalidArgument    = newClientError("C020001", "Invalid argument")
	ErrUnexpectedResponse = newClientError("C020002", "Unexpected response")
	ErrRateLimitExceeded  = newClientError("C020003", "Rate limit exceeded")

	// client functional errors
	ErrPublicKey        = newClientError("C030001", "Missing or invalid public key")
	ErrInvalidToken     = newClientError("C030002", "Invalid token")
	ErrRefreshToken     = newClientError("C030003", "Missing or invalid refresh token")
	ErrInvalidStepUpJWT = newClientError("C030004", "Refresh token must be provided for stepup actions")
)

var (
	ErrorInfoKeyRateLimitRetryAfter = "Retry-After"
)

type Error struct {
	Code        string         `json:"errorCode,omitempty"`
	Description string         `json:"errorDescription,omitempty"`
	Message     string         `json:"errorMessage,omitempty"`
	Info        map[string]any `json:"-"`
}

func (e Error) Error() string {
	str := fmt.Sprintf("[%s]", e.Code)
	if e.Description != "" && e.Message != "" {
		str = fmt.Sprintf("%s %s: %s", str, e.Description, e.Message)
	} else if e.Description != "" || e.Message != "" {
		str = fmt.Sprintf("%s %s%s", str, e.Description, e.Message)
	}
	if len(e.Info) > 0 {
		str = fmt.Sprintf("%s %v", str, e.Info)
	}
	return str
}

func (e Error) Is(err error) bool {
	if de, ok := err.(*Error); ok {
		return e.Code == de.Code
	}
	return false
}

func (e Error) WithMessage(format string, args ...any) *Error {
	return &Error{Code: e.Code, Description: e.Description, Message: fmt.Sprintf(format, args...)}
}

func newServerError(code string) *Error {
	return &Error{Code: code}
}

func newClientError(code, desc string) *Error {
	return &Error{Code: code, Description: desc}
}

func NewInvalidArgumentError(arg string) *Error {
	return ErrInvalidArgument.WithMessage(fmt.Sprintf("The '%s' argument is invalid", arg))
}
