package main

import (
	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/models"
)

func init() {
	config.LoadEnvVars()
	database.ConnectToDB()
}

func main() {
	// List all models
	database.DB.AutoMigrate(&models.User{})
	database.DB.AutoMigrate(&models.Item{})
}
