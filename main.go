package main

import (
	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/controllers"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	config.LoadEnvVars()
	database.ConnectToDB()
}

func main() {
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
