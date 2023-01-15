package errors

import "fmt"

const (
	BadRequestErrorCode           = "E01000"
	APIRateLimitExceededErrorCode = "E130429"
)

const (
	APIRateLimitRetryAfterHeader = "Retry-After"
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
	APIRateLimitExceeded       = NewAPIRateLimitError(APIRateLimitExceededErrorCode, "API rate limit exceeded")
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
		return fmt.Sprintf("[%s] description: %s, message: %s", e.Code, e.Description, e.Message)
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

type APIRateLimitError struct {
	*WebError
	RateLimitParameters map[string]string `json:"rateLimitParameters,omitempty"`
}

func (e *APIRateLimitError) Error() string {
	errStr := e.WebError.Error()
	for key, val := range e.RateLimitParameters {
		errStr += fmt.Sprintf(" %s: %s", key, val)
	}
	return errStr
}

func (e *APIRateLimitError) Is(err error) bool {
	if wErr, ok := err.(*APIRateLimitError); ok {
		if wErr.Code == e.Code {
			return true
		}
	}
	return false
}

func NewAPIRateLimitError(code, description string) *APIRateLimitError {
	return &APIRateLimitError{
		WebError: &WebError{
			Code:        code,
			Description: description,
		},
	}
}

func NewAPIRateLimitErrorFromResponse(code, description string, message string, rateLimitHeaders map[string]string) *APIRateLimitError {
	return &APIRateLimitError{
		WebError: &WebError{
			Code:        code,
			Description: description,
			Message:     message,
		},
		RateLimitParameters: rateLimitHeaders,
	}
}
