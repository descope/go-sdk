package errors

import "fmt"

const (
	BadRequestErrorCode = "E01000"
)

var (
	NoPublicKeyError          = NewPublicKeyValidationError("no public key was found for this project")
	FailedToRefreshTokenError = NewValidationError("refresh token not found")
	MissingProviderError      = NewValidationError("missing JWT provider implementation, use a built-in implementation or custom")
)

type WebError struct {
	Code    string `json:"error"`
	Message string `json:"message,omitempty"`
}

func NewFromError(code string, err error) *WebError {
	return NewError(code, err.Error())
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

func NewNoPublicKeyError() *PublicKeyValidationError {
	return NoPublicKeyError
}

func NewPublicKeyDoesNotMatchError() *WebError {
	return NewError(BadRequestErrorCode, "public key found is not compatible for given tokens")
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
