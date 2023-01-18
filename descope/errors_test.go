package descope

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorIs(t *testing.T) {
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo"})
	require.ErrorIs(t, ErrBadRequest, &Error{Code: ErrBadRequest.Code, Description: "foo", Message: "bar"})

	require.NotErrorIs(t, ErrBadRequest, &Error{})
	require.NotErrorIs(t, ErrBadRequest, ErrInvalidArgument)

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
