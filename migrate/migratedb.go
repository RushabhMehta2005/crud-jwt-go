package main

import (
	"log"

	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/models"
)

func main() {
	// Load environment variables
	if err := config.LoadEnvVars(); err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	// Connect to DB and get the local DB instance
	db, err := database.ConnectToDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("Running database migrations...")

	// Use the returned db instance to run AutoMigrate
	err = db.AutoMigrate(
		&models.User{},
		&models.Item{},
	)

	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("Database migrated successfully!")
}
