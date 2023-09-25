package models

import (
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Name               string
	Email              string
	Password           string
	PasswordResetToken string
	Photo              string
}
type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}
type ResetPasswordInput struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}
type Claims struct {
	Email string `json:"Email"`
	jwt.RegisteredClaims
}
