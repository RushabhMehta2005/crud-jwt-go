package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/RushabhMehta2005/crud-jwt/config"
	"github.com/RushabhMehta2005/crud-jwt/controllers"
	"github.com/RushabhMehta2005/crud-jwt/database"
	"github.com/gin-gonic/gin"
)

func main() {
	// Load environment variables from .env file
	if err := config.LoadEnvVars(); err != nil {
		log.Fatalf("Failed to load environment variables: %v", err)
	}

	// Connect to the database and get the DB instance
	db, err := database.ConnectToDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Create the single, central handler with its dependencies
	handler := controllers.NewHandler(db)

	// Setup router
	router := gin.Default()

	// Public authentication routes
	authRoutes := router.Group("/auth")
	{
		authRoutes.POST("/register", handler.Register)
		authRoutes.POST("/login", handler.Login)
		authRoutes.POST("/logout", handler.Logout)
	}

	// Protected API routes
	api := router.Group("/api", handler.RequireAuth) 
	{
		// User routes
		userRoutes := api.Group("/user")
		{
			userRoutes.GET("/profile", handler.GetProfile)
			userRoutes.PATCH("/password", handler.ChangePassword)
		}

		// Item routes
		itemRoutes := api.Group("/items")
		{
			itemRoutes.POST("", handler.CreateItem)
			itemRoutes.GET("", handler.ListItems)
			itemRoutes.GET("/:id", handler.GetItem)
			itemRoutes.PATCH("/:id", handler.UpdateItem)
			itemRoutes.DELETE("/:id", handler.DeleteItem)
		}
	}
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Configure and start the server
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Starting server on port %s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %s\n", err)
	}
}