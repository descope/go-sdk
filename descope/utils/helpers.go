package utils

import (
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
	return os.Getenv(EnvironmentVariablePublicKey)
}

func GetProjectIDEnvVariable() string {
	return os.Getenv(EnvironmentVariableProjectID)
}
