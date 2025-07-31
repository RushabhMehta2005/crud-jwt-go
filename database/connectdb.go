package database

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectToDB() error {
	var err error
	dsn := os.Getenv("DB_CREDENTIALS")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	return err
}
