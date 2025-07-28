package models

import "time"

type User struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Email    string `gorm:"unique"`
	Password string
	Items    []Item `gorm:"constraint:OnDelete:CASCADE;"`
}
