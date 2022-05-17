package auth

import "fmt"

const (
	badRequestErrorCode = "E01000"
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
	return NewError(badRequestErrorCode, fmt.Sprintf("invalid argument %s", arg))
}

func NewUnauthorizedError() *WebError {
	return NewError(badRequestErrorCode, "unauthorized access")
}

func NewNoPublicKeyError() *WebError {
	return NewError(badRequestErrorCode, "no public key was found for this project")
}

func NewPublicKeyDoesNotMatchError() *WebError {
	return NewError(badRequestErrorCode, "public key found is not compatible for given tokens")
}

func (e *WebError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
