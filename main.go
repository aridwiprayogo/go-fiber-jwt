package main

import (
	"fmt"
	"github.com/aridwiprayogo/golang-fiber-jwt/controller"
	"github.com/aridwiprayogo/golang-fiber-jwt/middleware"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"log"

	"github.com/aridwiprayogo/golang-fiber-jwt/initializers"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func init() {
	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Failed to load environment variables! \n", err.Error())
	}
	initializers.ConnectDB(&config)
}

func main() {
	app := fiber.New()
	micro := fiber.New()

	app.Mount("/api", micro)
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins:     "http://localhost:3000",
		AllowMethods:     "GET, POST",
		AllowHeaders:     "Origin, Content-Type, Accept",
		AllowCredentials: true,
	}))

	micro.Route("/auth", func(router fiber.Router) {
		router.Post("/register", controller.SignUpUser)
		router.Post("/login", controller.SignInUser)
		router.Post("/logout", middleware.DeserializeUser, controller.LogoutUser)
	})

	micro.Get("/user/me", middleware.DeserializeUser, controller.Getme)

	micro.Get("/api/healthChecker", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":  "success",
			"message": "Welcome to Golang, Fiber, and GORM",
		})
	})

	micro.All("*", func(ctx *fiber.Ctx) error {
		path := ctx.Path()
		return ctx.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"status":  "fail",
			"message": fmt.Sprintf("Path: %v does not exists on this server", path),
		})
	})

	log.Fatal(app.Listen(":8000"))
}
