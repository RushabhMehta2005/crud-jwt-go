package main

import (
	"log"

	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/models"
)

func main() {
	if err := config.LoadEnvVars(); err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}
	if err := database.ConnectToDB(); err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Running database migrations...")

    // Consolidate models
	err := database.DB.AutoMigrate(
		&models.User{},
		&models.Item{},
	)

	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database migrated successfully!")
}
