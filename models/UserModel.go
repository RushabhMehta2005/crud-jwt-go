package models

import "time"

type User struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Email    string `gorm:"unique;not null"`
	Password string `gorm:"not null"`
	Items    []Item `gorm:"constraint:OnDelete:CASCADE;"`
}
