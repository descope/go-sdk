package errors

import "fmt"

const (
	BadRequestErrorCode           = "E01000"
	ApiRateLimitExceededErrorCode = "E130429"
)

var (
	NoPublicKeyError           = NewPublicKeyValidationError("no public key was found for this project")
	FailedToRefreshTokenError  = NewValidationError("fail to refresh token")
	RefreshTokenError          = NewValidationError("refresh token invalid or not found")
	MissingProviderError       = NewValidationError("missing JWT provider implementation, use a built-in implementation or custom")
	InvalidPendingRefError     = NewValidationError("Invalid pending reference")
	InvalidAccessKeyResponse   = NewValidationError("invalid access key response received")
	EnchantedLinkUnauthorized  = NewValidationError("pending session token")
	UnauthorizedError          = NewError(BadRequestErrorCode, "unauthorized access")
	MissingRequestError        = NewValidationError("nil request provided")
	MissingResponseWriterError = NewValidationError("nil response writer provided")
	InvalidStepupJwtError      = NewValidationError("refresh JWT must be provided for stepup actions")
	ApiRateLimitExceeded       = NewError(ApiRateLimitExceededErrorCode, "API rate limit exceeded")
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
	return NewError(BadRequestErrorCode, fmt.Sprintf("the '%s' argument is invalid", arg))
}

func NewUnauthorizedError() *WebError {
	return UnauthorizedError
}

func NewNoPublicKeyError() *PublicKeyValidationError {
	return NoPublicKeyError
}

func (e *WebError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("[%s] %s, %s", e.Code, e.Description, e.Message)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *WebError) Is(err error) bool {
	if wErr, ok := err.(*WebError); ok {
		if wErr.Code == e.Code {
			return true
		}
	}
	return false
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

func (e *PublicKeyValidationError) Is(err error) bool {
	if vErr, ok := err.(*PublicKeyValidationError); ok {
		if vErr.Message == e.Message {
			return true
		}
	}
	return false
}

type ValidationError struct {
	Message string `json:"message,omitempty"`
}

func (e *ValidationError) Error() string {
	return e.Message
}

func (e *ValidationError) Is(err error) bool {
	if vErr, ok := err.(*ValidationError); ok {
		if vErr.Message == e.Message {
			return true
		}
	}
	return false
}

func NewValidationError(message string, args ...interface{}) *ValidationError {
	return &ValidationError{Message: fmt.Sprintf(message, args...)}
}
