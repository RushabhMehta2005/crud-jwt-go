package database

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)


// ConnectToDB creates and returns a new database connection instance.
func ConnectToDB() (*gorm.DB, error) {
	// Build DSN from individual environment variables for security and flexibility.
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
	)
    
    if os.Getenv("DB_HOST") == "" {
        return nil, fmt.Errorf("database environment variables not fully set")
    }

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		// Set logger to Silent to avoid logging every query in production.
		// Use logger.Info for development.
		Logger: logger.Default.LogMode(logger.Silent),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return db, nil
}