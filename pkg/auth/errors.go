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

func (e *WebError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}
