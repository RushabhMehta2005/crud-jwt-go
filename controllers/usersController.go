package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Register(c *gin.Context) {
	// Get Email and Password from request body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid register credentials",
		})
		return
	}

	// Hash the password
	const DEFAULT_COST int = 10

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), DEFAULT_COST)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to hash password",
		})
		return
	}

	// Create user and save to database
	user := models.User{Email: body.Email, Password: string(hash)}
	result := database.DB.Create(&user)

	// This can happen due to Email being a unique field
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to create user",
		})
		return
	}

	// Respond with 200 OK
	c.JSON(http.StatusOK, gin.H{
		"message": "User successfully registered.",
	})
}

func Login(c *gin.Context) {
	// Get email and password from request body
	var body struct {
		Email    string
		Password string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request body",
		})

		return
	}

	// Find user with that email (it is unique so only 1 user)
	var user models.User
	database.DB.Where("email = ?", body.Email).First(&user)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "No user found with that email",
		})
		return
	}

	// Check if hash of given password matches the stored hash
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid password",
		})
		return
	}

	const tokenLifeSpan int = 6 * 60 * 60 // 6 hours in seconds

	// Generate new JWT using HS256 algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID, // the information we want to encode (subject)
		"exp": time.Now().Add(time.Second * time.Duration(tokenLifeSpan)).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Could not generate new JWT",
		})
		return
	}

	// Add it to Cookie and Respond
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, tokenLifeSpan, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{})
}

func Validate(c *gin.Context) {
	// Just dummy protected route
	c.JSON(http.StatusOK, gin.H{
		"message": "I am logged in",
	})
}

func ChangePassword(c *gin.Context) {
	// Get the current password and new password off request body
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid payload"})
		return
	}

	// Get current user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Check if current password is correct
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Current password incorrect"})
		return
	}

	// Hash and update new password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
		return
	}

	// Update user in DB
	user.Password = string(hash)
	database.DB.Save(&user)

	// Return success response
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

func Logout(c *gin.Context) {
	// Clear the cookie on client
	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

func RefreshToken(c *gin.Context) {
	// Read existing token cookie
	tokenString, err := c.Cookie("Authorization")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "No token present"})
		return
	}

	// Parse without validating expiry so we can rotate
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	userID := uint(claims["sub"].(float64))

	// Issue a new token
	const tokenLifeSpan = 6 * 60 * 60 // 6 hours
	newTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Second * time.Duration(tokenLifeSpan)).Unix(),
	})

	newTokStr, err := newTok.SignedString([]byte(os.Getenv("SECRET_KEY")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not generate new token"})
		return
	}

	// Set new cookie
	c.SetCookie("Authorization", newTokStr, tokenLifeSpan, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed"})
}

func GetProfile(c *gin.Context) {
	// Get user from context
	u, _ := c.Get("user")
	user := u.(models.User)

	// Omit password from response
	user.Password = ""
	c.JSON(http.StatusOK, gin.H{"user": user})
}
