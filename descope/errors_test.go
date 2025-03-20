package descope

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorsIs(t *testing.T) {
	require.True(t, errors.Is(ErrBadRequest, &Error{Code: ErrBadRequest.Code}))
	require.True(t, errors.Is(ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo"}))
	require.True(t, errors.Is(ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo", Message: "bar"}))

	require.False(t, errors.Is(ErrBadRequest, &Error{}))
	require.False(t, errors.Is(ErrBadRequest, ErrInvalidArguments))

	require.True(t, errors.Is(ErrManagementUserNotFound, ErrManagementUserNotFound))
	require.False(t, errors.Is(ErrManagementUserNotFound, ErrBadRequest))

	require.False(t, errors.Is(nil, ErrBadRequest))
}

func TestErrorsAs(t *testing.T) {
	var de *Error
	require.False(t, errors.As(nil, &de))
	require.False(t, errors.As(errors.New("Some error"), &de))
	require.True(t, errors.As(ErrBadRequest, &de))
	require.Equal(t, ErrBadRequest.Code, de.Code)
	require.True(t, errors.As(fmt.Errorf("Some wrapped error: %w", ErrBadRequest), &de))
	require.Equal(t, ErrBadRequest.Code, de.Code)
}

func TestAssertError(t *testing.T) {
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo"})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo", Message: "bar"})

	require.NotErrorIs(t, ErrBadRequest, &Error{})
	require.NotErrorIs(t, ErrBadRequest, ErrInvalidArguments)

	require.ErrorIs(t, ErrManagementUserNotFound, ErrManagementUserNotFound)
	require.NotErrorIs(t, ErrManagementUserNotFound, ErrBadRequest)

	require.NotErrorIs(t, nil, ErrBadRequest)
}

func TestDescopeIs(t *testing.T) {
	require.True(t, (&Error{Code: ErrBadRequest.Code}).Is(ErrBadRequest))
	require.True(t, (&Error{Code: ErrBadRequest.Code, Description: "foo"}).Is(ErrBadRequest))
	require.True(t, (&Error{Code: ErrBadRequest.Code, Description: "foo", Message: "bar"}).Is(ErrBadRequest))

	require.False(t, (&Error{}).Is(ErrBadRequest))
	require.False(t, ErrInvalidArguments.Is(ErrBadRequest))

	require.True(t, ErrManagementUserNotFound.Is(ErrManagementUserNotFound))
	require.False(t, ErrBadRequest.Is(ErrManagementUserNotFound))

	var err error
	var de *Error
	require.False(t, de.Is(ErrBadRequest))
	require.False(t, de.Is(err))
}

func TestIsError(t *testing.T) {
	require.True(t, IsError(ErrManagementUserNotFound))
	require.True(t, IsError(ErrManagementUserNotFound, "E112102"))
	require.True(t, IsError(ErrManagementUserNotFound, "E112102", "E123456"))
	require.False(t, IsError(ErrManagementUserNotFound, "E123456"))
	require.False(t, IsError(nil))
	require.False(t, IsError(nil, "E112102"))
	require.False(t, IsError(errors.New("foo")))
}

func TestAsError(t *testing.T) {
	require.NotNil(t, AsError(ErrManagementUserNotFound))
	require.NotNil(t, AsError(ErrManagementUserNotFound, "E112102"))
	require.NotNil(t, AsError(ErrManagementUserNotFound, "E112102", "E123456"))
	require.NotNil(t, AsError(fmt.Errorf("Some wrapped error: %w", ErrManagementUserNotFound)), "E112102")
	require.Nil(t, AsError(ErrManagementUserNotFound, "E123456"))
	require.Nil(t, AsError(nil))
	require.Nil(t, AsError(nil, "E112102"))
	require.Nil(t, AsError(errors.New("foo")))
}

func TestErrorPrint(t *testing.T) {
	err := &Error{Code: "foo"}
	require.Equal(t, "[foo]", err.Error())
	err.Description = "bar"
	require.Equal(t, "[foo] bar", err.Error())
	err.Message = "qux"
	require.Equal(t, "[foo] bar: qux", err.Error())
	err.Description = ""
	require.Equal(t, "[foo] qux", err.Error())
}

func TestWithArg(t *testing.T) {
	x := &Error{Code: "E123"}
	require.Equal(t, "[E123]", x.Error())

	y := x.WithMessage("b")
	require.Equal(t, "[E123] b", y.Error())
	require.Equal(t, "[E123]", x.Error())

	z := y.WithInfo("qux", 7)
	require.Equal(t, "[E123] b [qux:7]", z.Error())
	require.Equal(t, "[E123] b", y.Error())

	z = z.WithInfo("url", `http://example`)
	require.Equal(t, "[E123] b [qux:7 url:http://example]", z.Error())
}

func TestStatusCode(t *testing.T) {
	badreq := newServerError("E123").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 400)
	unauth := newServerError("E234").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 401)
	forb := newServerError("E345").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 403)
	notfound := newServerError("E456").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 404)
	other := newServerError("E567").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 500)
	require.True(t, IsBadRequestError(badreq))
	require.True(t, IsUnauthorizedError(unauth))
	require.True(t, IsForbidden(forb))
	require.True(t, IsNotFoundError(notfound))
	require.False(t, IsBadRequestError(nil))
	require.False(t, IsUnauthorizedError(nil))
	require.False(t, IsForbidden(nil))
	require.False(t, IsNotFoundError(nil))
	require.False(t, IsBadRequestError(other))
	require.False(t, IsUnauthorizedError(other))
	require.False(t, IsForbidden(other))
	require.False(t, IsNotFoundError(other))
	require.False(t, IsBadRequestError(assert.AnError))
	require.False(t, IsUnauthorizedError(assert.AnError))
	require.False(t, IsForbidden(assert.AnError))
	require.False(t, IsNotFoundError(assert.AnError))
}
