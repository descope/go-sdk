package descope

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
)

var (
	// server common

	ErrBadRequest        = newServerError("E011001")
	ErrMissingArguments  = newServerError("E011002")
	ErrValidationFailure = newServerError("E011003")
	ErrInvalidArguments  = newServerError("E011004")

	// server authentication

	ErrUserAlreadyExists         = newServerError("E062107")
	ErrInvalidOneTimeCode        = newServerError("E061102")
	ErrEnchantedLinkUnauthorized = newServerError("E062503")
	ErrPasswordExpired           = newServerError("E062909")
	ErrTokenExpiredByLoggedOut   = newServerError("E064001")
	ErrNOTPUnauthorized          = newServerError("E066103")

	// server management

	ErrManagementUserNotFound = newServerError("E112102")

	// server infra

	ErrRateLimitExceeded = newServerError("E130429")

	// client setup

	ErrMissingProjectID = newClientError("G010001", "Missing project ID")

	// client service error

	ErrUnexpectedResponse = newClientError("G020001", "Unexpected server response")
	ErrInvalidResponse    = newClientError("G020002", "Invalid server response")

	// client functional errors

	ErrPublicKey        = newClientError("G030001", "Missing or invalid public key")
	ErrInvalidToken     = newClientError("G030002", "Invalid token")
	ErrRefreshToken     = newClientError("G030003", "Missing or invalid refresh token")
	ErrInvalidStepUpJWT = newClientError("G030004", "Refresh token must be provided for stepup actions")
)

// Additional information that might be available in the
// Error struct's Info map for specific errors
var ErrorInfoKeys = errorInfoKeys{
	HTTPResponseStatusCode:      "Status-Code",
	RateLimitExceededRetryAfter: "Retry-After",
}

// The type of error returned by the Descope SDK in most circumstances.
type Error struct {
	// A non-empty code for the specific error condition
	Code string `json:"errorCode,omitempty"`

	// a non-empty description of the error condition.
	Description string `json:"errorDescription,omitempty"`

	// an optional message with more specific details about the error.
	Message string `json:"errorMessage,omitempty"`

	// an optional map with additional metadata about the error.
	Info map[string]any `json:"-"`
}

// A convenience function for checking if a generic error value is a Descope error, and
// optionally also checking that it matches 1 or more specific error codes.
//
//	if descope.IsError(err, "E061103") {
//	  fmt.Println("Too many OTP attempts")
//	}
func IsError(err error, errorCode ...string) bool {
	return AsError(err, errorCode...) != nil
}

// A convenience function for checking if a generic error value is a Descope error, and
// optionally also checking that it matches 1 or more specific error codes, in which case
// it returns the error value as a *descope.Error, otherwise it returns nil.
//
//	if err := descope.AsError(err, "E061103") {
//	  fmt.Printf("The operation failed: %v", err)
//	}
func AsError(err error, errorCode ...string) *Error {
	var de *Error
	if errors.As(err, &de) {
		if len(errorCode) == 0 || slices.Contains(errorCode, de.Code) {
			return de
		}
	}
	return nil
}

// Returns whether an error value is a Descope server error with a 400 HTTP status code.
func IsBadRequestError(err error) bool {
	return AsError(err).IsBadRequest()
}

// Returns whether an error value is a Descope server error with a 401 HTTP status code.
func IsUnauthorizedError(err error) bool {
	return AsError(err).IsUnauthorized()
}

// Returns whether an error value is a Descope server error with a 403 HTTP status code.
func IsForbidden(err error) bool {
	return AsError(err).IsForbidden()
}

// Returns whether an error value is a Descope server error with a 404 HTTP status code.
func IsNotFoundError(err error) bool {
	return AsError(err).IsNotFound()
}

// Returns whether the error value matches this Descope error.
func (e *Error) Is(err error) bool {
	if de, ok := err.(*Error); ok { // this must be a shallow check - no calls to Unwrap, errors.Is, or errors.As
		return e != nil && e.Code == de.Code
	}
	return false
}

// Returns a string representation of this Descope error, including all of its field.
// For a user friendly error message use the value of the Description field.
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

// Returns a new Error instance with a new value for the Message field.
func (e Error) WithMessage(format string, args ...any) *Error {
	e.Message = fmt.Sprintf(format, args...)
	return &e
}

// Returns a new Error instance with a new value for the Info field.
func (e Error) WithInfo(key string, value any) *Error {
	if e.Info == nil {
		e.Info = map[string]any{}
	}
	e.Info[key] = value
	return &e
}

// Returns whether this is a server error with a 400 HTTP status code.
func (e *Error) IsBadRequest() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusBadRequest
}

// Returns whether this is a server error with a 401 HTTP status code.
func (e *Error) IsUnauthorized() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusUnauthorized
}

// Returns whether this is a server error with a 403 HTTP status code.
func (e *Error) IsForbidden() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusForbidden
}

// Returns whether this is a server error with a 404 HTTP status code.
func (e *Error) IsNotFound() bool {
	return e != nil && e.Info[ErrorInfoKeys.HTTPResponseStatusCode] == http.StatusNotFound
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
