package descope

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorIs(t *testing.T) {
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo"})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo", Message: "bar"})

	require.NotErrorIs(t, ErrBadRequest, &Error{})
	require.NotErrorIs(t, ErrBadRequest, ErrInvalidArguments)

	require.ErrorIs(t, ErrManagementUserNotFound, ErrManagementUserNotFound)
	require.NotErrorIs(t, ErrManagementUserNotFound, ErrBadRequest)
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

func TestIsError(t *testing.T) {
	require.True(t, IsError(ErrBadRequest))
	require.False(t, IsError(nil))
	require.False(t, IsError(assert.AnError))
}

func TestStatusCode(t *testing.T) {
	unauth := newServerError("E123").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 401)
	notfound := newServerError("E234").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 404)
	other := newServerError("E345").WithInfo(ErrorInfoKeys.HTTPResponseStatusCode, 500)
	require.True(t, IsUnauthorizedError(unauth))
	require.True(t, IsNotFoundError(notfound))
	require.False(t, IsUnauthorizedError(nil))
	require.False(t, IsNotFoundError(nil))
	require.False(t, IsUnauthorizedError(other))
	require.False(t, IsNotFoundError(other))
	require.False(t, IsUnauthorizedError(assert.AnError))
	require.False(t, IsNotFoundError(assert.AnError))
}
