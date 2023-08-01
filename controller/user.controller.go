package controller

import (
	"github.com/aridwiprayogo/golang-fiber-jwt/models"
	"github.com/gofiber/fiber/v2"
)

func Getme(ctx *fiber.Ctx) error {
	user := ctx.Locals("user").(models.UserResponse)

	return ctx.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "success",
		"data": fiber.Map{
			"user": user,
		},
	})
}
