package auth

import (
	"context"
	"encoding/json"
	"os"
)

// Marshal - any given object into json
func Marshal(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// Unmarshal from json any given object
func Unmarshal(bs []byte, obj interface{}) error {
	return json.Unmarshal(bs, obj)
}

func GetPublicKeyEnvVariable() string {
	return os.Getenv(environmentVariablePublicKey)
}

func GetProjectIDEnvVariable() string {
	return os.Getenv(environmentVariableProjectID)
}

func GetValueAsString(ctx context.Context, key string) string {
	val := ctx.Value(key)
	if val == nil {
		return ""
	}
	strVal, ok := val.(string)
	if !ok {
		return ""
	}
	return strVal
}
