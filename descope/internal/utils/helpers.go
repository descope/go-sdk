package utils

import (
	"encoding/json"
	"os"

	"github.com/descope/go-sdk/v2/descope"
)

// Marshal - any given object into json
func Marshal(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// Unmarshal from json any given object
func Unmarshal(bs []byte, obj interface{}) error {
	return json.Unmarshal(bs, obj)
}

func GetProjectIDEnvVariable() string {
	return os.Getenv(descope.EnvironmentVariableProjectID)
}

func GetManagementKeyEnvVariable() string {
	return os.Getenv(descope.EnvironmentVariableManagementKey)
}

func GetPublicKeyEnvVariable() string {
	return os.Getenv(descope.EnvironmentVariablePublicKey)
}
