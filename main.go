package main

import (
	"log"

	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/controllers"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/middleware"
	"github.com/gin-gonic/gin"
)


func main() {

	err := config.LoadEnvVars()

	if err != nil {
		log.Fatalf("Failed to load environment variables: %v", err)
	}

	err = database.ConnectToDB()

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	router := gin.Default()

	// Public routes
	router.POST("/register", controllers.Register)
	router.POST("/login", controllers.Login)

	// Protected routes - Authentication
	router.GET("/validate", middleware.RequireAuth, controllers.Validate)
	router.PATCH("/user/password", middleware.RequireAuth, controllers.ChangePassword)
	router.POST("/logout", middleware.RequireAuth, controllers.Logout)
	router.POST("/user/refresh", middleware.RequireAuth, controllers.RefreshToken)
	router.GET("/user/profile", middleware.RequireAuth, controllers.GetProfile)

	// Protected routes - Items
	router.GET("/item", middleware.RequireAuth, controllers.ListItems)
	router.POST("/item", middleware.RequireAuth, controllers.CreateItem)
	router.GET("/item/:id", middleware.RequireAuth, controllers.GetItem)
	router.PATCH("/item/:id", middleware.RequireAuth, controllers.UpdateItem)
	router.DELETE("/item/:id", middleware.RequireAuth, controllers.DeleteItem)

	router.Run()
}
