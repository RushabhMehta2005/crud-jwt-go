package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/controllers"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/RushabhMehta2005/crud-jwt/middleware"
	"github.com/gin-gonic/gin"
)


func main() {

	// Application setup
	err := config.LoadEnvVars()

	if err != nil {
		log.Fatalf("Failed to load environment variables: %v", err)
	}

	err = database.ConnectToDB()

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Application Routes
	router := gin.Default()

	// Public auth routes
    authRoutes := router.Group("/auth")
    {
        authRoutes.POST("/register", controllers.Register)
        authRoutes.POST("/login", controllers.Login)
        authRoutes.POST("/refresh", controllers.RefreshToken)
    }

    // Protected API routes
    api := router.Group("/api")
    api.Use(middleware.RequireAuth)
    {
        // User routes
        userRoutes := api.Group("/user")
        {
            userRoutes.GET("/profile", controllers.GetProfile)
            userRoutes.PATCH("/password", controllers.ChangePassword)
        }

        // Item routes
        itemRoutes := api.Group("/items")
        {
            itemRoutes.GET("", controllers.ListItems)
            itemRoutes.POST("", controllers.CreateItem)
            itemRoutes.GET("/:id", controllers.GetItem)
            itemRoutes.PATCH("/:id", controllers.UpdateItem)
            itemRoutes.DELETE("/:id", controllers.DeleteItem)
        }
    }

	server := &http.Server{
        Addr:         os.Getenv("PORT"),
        Handler:      router,
        ReadTimeout:  5 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    log.Println("Starting server on port 8080")
    if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
        log.Fatalf("listen: %s\n", err)
    }
}
