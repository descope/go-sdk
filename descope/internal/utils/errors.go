package utils

import (
	"github.com/descope/go-sdk/descope"
)

func NewInvalidArgumentError(arg string) *descope.Error {
	return descope.ErrInvalidArguments.WithMessage("The %s argument is invalid", arg)
}
