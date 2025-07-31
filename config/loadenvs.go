package config

import (
	"github.com/joho/godotenv"
)

func LoadEnvVars() error {
	err := godotenv.Load()
	return err
}
