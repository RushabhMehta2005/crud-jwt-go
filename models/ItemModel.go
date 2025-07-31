package models

import "time"

type Item struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Name     string `gorm:"not null"`
    Price    float32
    Quantity int    `gorm:"not null"`
    UserID   uint   `gorm:"not null;index"`
}
