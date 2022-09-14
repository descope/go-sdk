package errors

import "fmt"

const (
	BadRequestErrorCode = "E01000"
)

var (
	NoPublicKeyError          = NewPublicKeyValidationError("no public key was found for this project")
	FailedToRefreshTokenError = NewValidationError("fail to refresh token")
	RefreshTokenError         = NewValidationError("refresh token invalid or not found")
	MissingProviderError      = NewValidationError("missing JWT provider implementation, use a built-in implementation or custom")
	InvalidPendingRefError    = NewValidationError("Invalid pending reference")
	MissingAccessKeyError     = NewValidationError("authorization header must include project and key")
	InvalidAccessKeyResponse  = NewValidationError("invalid access key response received")
	MagicLinkUnauthorized     = NewValidationError("pending session token")
	UnauthorizedError         = NewError(BadRequestErrorCode, "unauthorized access")
)

type WebError struct {
	Code        string `json:"errorCode,omitempty"`
	Description string `json:"errorDescription,omitempty"`
	Message     string `json:"message,omitempty"`
}

func NewError(code, message string) *WebError {
	return &WebError{Code: code, Message: message}
}

func NewInvalidArgumentError(arg string) *WebError {
	return NewError(BadRequestErrorCode, fmt.Sprintf("invalid argument %s", arg))
}

func NewUnauthorizedError() *WebError {
	return UnauthorizedError
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
