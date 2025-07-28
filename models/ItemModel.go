package models

import "time"

type Item struct {
	ID        uint `gorm:"primarykey"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Name     string
	Price    float32
	Quantity int
	UserID   uint
}
