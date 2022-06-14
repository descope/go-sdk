package errors

import "fmt"

const (
	BadRequestErrorCode     = "E01000"
	PendingSessionErrorCode = "E01001"
)

var (
	NoPublicKeyError          = NewPublicKeyValidationError("no public key was found for this project")
	FailedToRefreshTokenError = NewValidationError("fail to refresh token")
	RefreshTokenError         = NewValidationError("refresh token invalid or not found")
	MissingProviderError      = NewValidationError("missing JWT provider implementation, use a built-in implementation or custom")
	InvalidPendingRefError    = NewValidationError("Invalid pending reference")
	MissingSessionTokenError  = NewValidationError("missing session token")
)

type WebError struct {
	Code    string `json:"error"`
	Message string `json:"message,omitempty"`
}

func NewError(code, message string) *WebError {
	return &WebError{Code: code, Message: message}
}

func NewInvalidArgumentError(arg string) *WebError {
	return NewError(BadRequestErrorCode, fmt.Sprintf("invalid argument %s", arg))
}

func NewUnauthorizedError() *WebError {
	return NewError(BadRequestErrorCode, "unauthorized access")
}

func NewPendingSessionTokenError() *WebError {
	return NewError(PendingSessionErrorCode, "pending session token")
}

func NewNoPublicKeyError() *PublicKeyValidationError {
	return NoPublicKeyError
}

func (e *WebError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

type PublicKeyValidationError struct {
	Message string `json:"message,omitempty"`
}

func NewPublicKeyValidationError(message string, args ...interface{}) *PublicKeyValidationError {
	return &PublicKeyValidationError{Message: fmt.Sprintf(message, args...)}
}

func (e *PublicKeyValidationError) Error() string {
	return e.Message
}

type ValidationError struct {
	Message string `json:"message,omitempty"`
}

func (e *ValidationError) Error() string {
	return e.Message
}

func NewValidationError(message string, args ...interface{}) *ValidationError {
	return &ValidationError{Message: fmt.Sprintf(message, args...)}
}

func IsError(err error, code string) bool {
	if err == nil {
		return false
	}
	if err.Error() == code {
		return true
	}
	if e, ok := err.(*WebError); ok {
		return e.Code == code
	}
	return false
}
