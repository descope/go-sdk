package utils

import (
	"fmt"

	"github.com/descope/go-sdk/descope"
)

func NewInvalidArgumentError(arg string) *descope.Error {
	return descope.ErrInvalidArguments.WithMessage(fmt.Sprintf("The %s argument is invalid", arg))
}
