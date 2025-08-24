package controllers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/RushabhMehta2005/crud-jwt/models"
	"github.com/RushabhMehta2005/crud-jwt/services"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	authCookieName  = "Authorization"
	jwtExpiration   = 6 * time.Hour
	bcryptCost      = 12
	cacheDefaultExp = 5 * time.Minute
	cacheCleanupInt = 10 * time.Minute
)

// Handler holds the application's dependencies, making them explicit.
type Handler struct {
	DB        *gorm.DB
	JWTSecret string
	Hasher    *services.Hasher
	UserCache *cache.Cache
}

// NewHandler creates a new handler with its dependencies.
func NewHandler(db *gorm.DB) *Handler {
	jwtSecret := os.Getenv("SECRET_KEY")
	if jwtSecret == "" {
		panic("SECRET_KEY environment variable not set")
	}

	// Create the hasher service with a worker for each available CPU core.
	hasher := services.NewHasher(runtime.NumCPU(), bcryptCost)

	// Create the in-memory cache.
	userCache := cache.New(cacheDefaultExp, cacheCleanupInt)

	return &Handler{
		DB:        db,
		JWTSecret: jwtSecret,
		Hasher:    hasher,
		UserCache: userCache,
	}
}

// RequireAuth is a middleware to protect routes that require authentication.
// now optimized with a caching layer.
func (h *Handler) RequireAuth(c *gin.Context) {
	tokenString, err := c.Cookie(authCookieName)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, "Authorization token required")
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.JWTSecret), nil
	})

	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		h.jsonError(c, http.StatusUnauthorized, "Invalid token claims")
		return
	}

	userIDFloat, ok := claims["sub"].(float64)
	if !ok {
		h.jsonError(c, http.StatusUnauthorized, "Invalid user ID in token")
		return
	}
	userID := uint(userIDFloat)

	// --- Caching Logic Starts Here ---
	cacheKey := fmt.Sprintf("user:%d", userID)

	// Check cache first
	if cachedUser, found := h.UserCache.Get(cacheKey); found {
		if user, ok := cachedUser.(models.User); ok {
			c.Set("user", user)
			c.Next()
			return
		}
	}

	// Cache miss: Fetch from DB
	var user models.User
	if err := h.DB.First(&user, userID).Error; err != nil {
		h.jsonError(c, http.StatusUnauthorized, "User not found")
		return
	}

	// Populate cache
	h.UserCache.Set(cacheKey, user, cache.DefaultExpiration)

	c.Set("user", user)
	c.Next()
}

// ## User Handlers

// Register now offloads hashing to the worker pool.
func (h *Handler) Register(c *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// Offload the slow hashing operation.
	hash, err := h.Hasher.GenerateHash(body.Password)
	if err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	user := models.User{Email: body.Email, Password: hash}
	if result := h.DB.Create(&user); result.Error != nil {
		h.jsonError(c, http.StatusBadRequest, "Failed to create user, email may be taken")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User successfully registered"})
}

func (h *Handler) Login(c *gin.Context) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	var user models.User
	if err := h.DB.Where("email = ?", body.Email).First(&user).Error; err != nil {
		h.jsonError(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		h.jsonError(c, http.StatusUnauthorized, "Invalid email or password")
		return
	}

	tokenString, err := h.createJWT(user.ID)
	if err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Could not generate token")
		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(authCookieName, tokenString, int(jwtExpiration.Seconds()), "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func (h *Handler) Logout(c *gin.Context) {
	// To logout, we expire the cookie immediately by setting its maxAge to a negative value.
	c.SetCookie(authCookieName, "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

func (h *Handler) Check(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Health is healthy."})
}

func (h *Handler) GetProfile(c *gin.Context) {
	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":        user.ID,
			"email":     user.Email,
			"createdAt": user.CreatedAt,
		},
	})
}

// ChangePassword offloads hashing and invalidates the cache.
func (h *Handler) ChangePassword(c *gin.Context) {
	var body struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.CurrentPassword)); err != nil {
		h.jsonError(c, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	// Offload the new password hashing.
	newHash, err := h.Hasher.GenerateHash(body.NewPassword)
	if err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to hash new password")
		return
	}

	user.Password = newHash
	if err := h.DB.Save(&user).Error; err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to update password")
		return
	}
	
	// CRITICAL: Invalidate the cache for this user.
	cacheKey := fmt.Sprintf("user:%d", user.ID)
	h.UserCache.Delete(cacheKey)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// ## Item Handlers

func (h *Handler) CreateItem(c *gin.Context) {
	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var body struct {
		Name     string 	`json:"name" binding:"required"`
		Price    float32    `json:"price" binding:"required,gte=0"`
		Quantity int    	`json:"quantity" binding:"required,gte=0"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid request body: " + err.Error())
		return
	}

	item := models.Item{
		Name:     body.Name,
		Price:    body.Price,
		Quantity: body.Quantity,
		UserID:   user.ID,
	}

	if result := h.DB.Create(&item); result.Error != nil {
		h.jsonError(c, http.StatusInternalServerError, "Could not save item")
		return
	}

	c.JSON(http.StatusCreated, gin.H{"item": item})
}

func (h *Handler) ListItems(c *gin.Context) {
	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var items []models.Item
	if err := h.DB.Where("user_id = ?", user.ID).Find(&items).Error; err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to fetch items")
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *Handler) GetItem(c *gin.Context) {
	itemID, err := h.parseID(c.Param("id"))
	if err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid item ID")
		return
	}

	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var item models.Item
	err = h.DB.Where("id = ? AND user_id = ?", itemID, user.ID).First(&item).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		h.jsonError(c, http.StatusNotFound, "Item not found")
		return
	}
	if err != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to fetch item")
		return
	}

	c.JSON(http.StatusOK, gin.H{"item": item})
}

func (h *Handler) UpdateItem(c *gin.Context) {
	itemID, err := h.parseID(c.Param("id"))
	if err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid item ID")
		return
	}

	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	var body struct {
		Name     *string `json:"name"`
		Price    *int    `json:"price"`
		Quantity *int    `json:"quantity"`
	}
	if err := c.Bind(&body); err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid payload")
		return
	}

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
		h.jsonError(c, http.StatusBadRequest, "No fields to update")
		return
	}
	
	var updatedItem models.Item
	result := h.DB.Model(&updatedItem).
		Clauses(clause.Returning{}).
		Where("id = ? AND user_id = ?", itemID, user.ID).
		Updates(updates)

	if result.Error != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to update item")
		return
	}
	if result.RowsAffected == 0 {
		h.jsonError(c, http.StatusNotFound, "Item not found or you don't have permission to update it")
		return
	}

	c.JSON(http.StatusOK, gin.H{"item": updatedItem})
}

func (h *Handler) DeleteItem(c *gin.Context) {
	itemID, err := h.parseID(c.Param("id"))
	if err != nil {
		h.jsonError(c, http.StatusBadRequest, "Invalid item ID")
		return
	}

	user, err := h.getUserFromContext(c)
	if err != nil {
		h.jsonError(c, http.StatusUnauthorized, err.Error())
		return
	}

	result := h.DB.Where("id = ? AND user_id = ?", itemID, user.ID).Delete(&models.Item{})
	if result.Error != nil {
		h.jsonError(c, http.StatusInternalServerError, "Failed to delete item")
		return
	}
	if result.RowsAffected == 0 {
		h.jsonError(c, http.StatusNotFound, "Item not found or you don't have permission to delete it")
		return
	}

	c.Status(http.StatusNoContent)
}

// ## Helper Methods

func (h *Handler) jsonError(c *gin.Context, code int, message string) {
	c.AbortWithStatusJSON(code, gin.H{"error": message})
}

func (h *Handler) getUserFromContext(c *gin.Context) (models.User, error) {
	u, exists := c.Get("user")
	if !exists {
		return models.User{}, errors.New("user not found in context")
	}
	user, ok := u.(models.User)
	if !ok {
		return models.User{}, errors.New("invalid user type in context")
	}
	return user, nil
}

func (h *Handler) createJWT(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(jwtExpiration).Unix(),
	})
	return token.SignedString([]byte(h.JWTSecret))
}

func (h *Handler) parseID(idStr string) (uint, error) {
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint(id), nil
}
