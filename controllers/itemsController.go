package controllers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/models"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func ListItems(c *gin.Context) {
	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Get all items associated with this user
	var items []models.Item
	if err := database.DB.
		Where("user_id = ?", user.ID).
		Find(&items).
		Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch items"})
		return
	}

	// Return response
	c.JSON(http.StatusOK, gin.H{
		"items": items,
	})
}

func CreateItem(c *gin.Context) {
	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Get item fields from request body
	var body struct {
		Name     string
		Price    float32
		Quantity int
	}

	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid payload"})
		return
	}

	// Create item object
	item := models.Item{Name: body.Name, Price: body.Price, Quantity: body.Quantity, UserID: user.ID}

	result := database.DB.Create(&item)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save item"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"item": item,
	})
}

func GetItem(c *gin.Context) {
	// Parse and validate the ID
	idParam := c.Param("id")
	itemID, err := strconv.ParseUint(idParam, 10, 64)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Fetch the item, scoped to this user
	var item models.Item
	result := database.DB.
		Where("id = ? AND user_id = ?", itemID, user.ID).
		First(&item)

	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
		return
	}

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch item"})
		return
	}

	// Return response
	c.JSON(http.StatusOK, gin.H{"item": item})
}

func DeleteItem(c *gin.Context) {
	// Parse and validate the ID
	idParam := c.Param("id")
	itemID, err := strconv.ParseUint(idParam, 10, 64)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Find and delete this item from db (Single round‑trip to the database, instead of fetch‑then‑delete)
	result := database.DB.
		Where("id = ? AND user_id = ?", itemID, user.ID).
		Delete(&models.Item{})

	if result.Error != nil {
		// e.g. DB connectivity issue
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete item"})
		return
	}

	if result.RowsAffected == 0 {
		// Either it didn’t exist, or it wasn’t owned by this user
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
		return
	}

	// Return success response
	c.Status(http.StatusNoContent)
}

func UpdateItem(c *gin.Context) {
	// Parse and validate the ID
	idParam := c.Param("id")
	itemID, err := strconv.ParseUint(idParam, 10, 64)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid item ID"})
		return
	}

	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Bind optional fields
	var body struct {
		Name     *string  `json:"name"`
		Price    *float32 `json:"price"`
		Quantity *int     `json:"quantity"`
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	// Build map of fields to update
	updates := make(map[string]interface{})
	if body.Name != nil {
		updates["name"] = *body.Name
	}
	if body.Price != nil {
		updates["price"] = *body.Price
	}
	if body.Quantity != nil {
		updates["quantity"] = *body.Quantity
	}
	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	// Perform conditional update
	result := database.DB.
		Model(&models.Item{}).
		Where("id = ? AND user_id = ?", itemID, user.ID).
		Updates(updates)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update item"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Item not found"})
		return
	}

	// Reload the updated item
	var updatedItem models.Item
	if err := database.DB.
		Where("id = ? AND user_id = ?", itemID, user.ID).
		First(&updatedItem).
		Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch updated item"})
		return
	}

	// Return the updated item
	c.JSON(http.StatusOK, gin.H{"item": updatedItem})
}
