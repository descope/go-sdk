package errors

import (
	"fmt"
)

var (
	// server common
	ErrBadRequest        = newServerError("E011001")
	ErrInvalidArguments  = newServerError("E011002")
	ErrValidationFailure = newServerError("E011003")

	// server authentication
	ErrEnchantedLinkUnauthorized = newServerError("E062503")

	// server management
	ErrManagementUserNotFound = newServerError("E112102")

	// client setup
	ErrMissingProjectID = newClientError("C010001", "Missing project ID")

	// client service error
	ErrInvalidArgument    = newClientError("C020001", "Invalid argument")
	ErrUnexpectedResponse = newClientError("C020002", "Unexpected response")

	// client functional errors
	ErrPublicKey        = newClientError("C030001", "Missing or invalid public key")
	ErrInvalidToken     = newClientError("C030002", "Invalid token")
	ErrRefreshToken     = newClientError("C030003", "Missing or invalid refresh token")
	ErrInvalidStepUpJWT = newClientError("C030004", "Refresh token must be provided for stepup actions")
)

type DescopeError struct {
	Code        string `json:"errorCode,omitempty"`
	Description string `json:"errorDescription,omitempty"`
	Message     string `json:"errorMessage,omitempty"`
}

func (e DescopeError) Error() string {
	str := fmt.Sprintf("[%s] %s", e.Code, e.Description)
	if e.Message != "" {
		str = fmt.Sprintf("%s: %s", str, e.Message)
	}
	return str
}

func (e DescopeError) Is(err error) bool {
	if de, ok := err.(*DescopeError); ok {
		return e.Code == de.Code
	}
	return false
}

func (e DescopeError) WithMessage(format string, args ...any) *DescopeError {
	return &DescopeError{Code: e.Code, Description: e.Description, Message: fmt.Sprintf(format, args...)}
}

func newServerError(code string) *DescopeError {
	return &DescopeError{Code: code}
}

func newClientError(code, desc string) *DescopeError {
	return &DescopeError{Code: code, Description: desc}
}

func NewInvalidArgumentError(arg string) *DescopeError {
	return ErrInvalidArgument.WithMessage(fmt.Sprintf("The '%s' argument is invalid", arg))
}
