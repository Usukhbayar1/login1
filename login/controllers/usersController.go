package controllers

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/thanhpk/randstr"
	"github.com/usukhbayar/login/initializers"
	"github.com/usukhbayar/login/models"
	"golang.org/x/crypto/bcrypt"
)


func Signup(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Fail to read body",
		})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Fail hash pass",
		})
		return
	}
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initializers.DB.Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Fail create user",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{})
}
func Login(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}
	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Fail to read body",
		})
		return
	}
	var user models.User
	initializers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "bruu pass email",
		})
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "bruu pass email",
		})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "token",
		})
		return
	}
	w.Header().Add("Authorization", "Bearer "+token) 
	c.JSON(http.StatusOK, gin.H{})
}
func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": user,
	})
}

func ForgotPassword(c *gin.Context) {
		var payload *models.ForgotPasswordInput
	
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
			return
		}
	
		message := "You will receive a reset email if user with that email exist"
	
		var user models.User
		result := initializers.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
		if result.Error != nil {
			c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Invalid email or Password"})
			return
		}
	
	
		// Generate Verification Code
		resetToken := randstr.String(20)
	
		passwordResetToken := resetToken
		user.PasswordResetToken = passwordResetToken
		initializers.DB.Save(&user)
	
		var Email = user.Email
	
		if strings.Contains(Email, " ") {
			Email = strings.Split(Email, " ")[1]
		}
	
		from = "torjlor4@gmail.com"
		to := []string {
			 Email,
		}
		url := "http//localhost:3000/reset/"+ passwordResetToken
		message :=[]byte("click <a href=\"" + url + "\" >here</a>")

		smtp.SendMail( addr:"" ,a:nil,from,to,message)

		c.JSON(http.StatusOK, gin.H{"status": "success", "message": message})
	
	
}
func ResetPassword(c *gin.Context) {
	var payload *models.ResetPasswordInput
	resetToken := c.Params.ByName("resetToken")

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": err.Error()})
		return
	}

	if payload.Password != payload.PasswordConfirm {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "Passwords do not match"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Fail hash pass",
		})
		return
	}
    passwordResetToken := resetToken

	var updatedUser models.User
	result := initializers.DB.First(&updatedUser, "password_reset_token = ?", passwordResetToken, )
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "fail", "message": "The reset token is invalid or has expired"})
		return
	}

	
	updatedUser.PasswordResetToken = ""
	initializers.DB.Save(&updatedUser)

	c.SetCookie("token", "", -1, "/", "localhost", false, true)

	c.JSON(http.StatusOK, gin.H{"status": "success", "message": "Password data updated successfully"})
}
func UserDetails(c *gin.Context){
	c, err := r.Header.Get("Authorization")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	tknStr := c.Value

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (any, error) {
		return jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
    var body struct{
		Name string 
		Email string 
	}
    c.Bind(&body)
    
	var user models.User
	initializers.DB.first(&user,id)

	initializers.DB.Model(&user).Update(model.user{
		Name: body.Name,
		Email: body.Email,
	})
	c.JSON(http.StatusOK, gin.H{})
}
func UplaodImage(c *gin.Context){
	file.err:=c.FormFile("image")
	if err!=nil {
	c.JSON(http.StatusBadRequest, gin.H{
		"fail upload",
	})
	return
  }
 filename:= strings.Replace(id.string(),"-","",-1)
 fileExt:=strings.Split(file.filename,".")[1]
 image:=fmt.Sprintf("%s.%s",filename,fileExt)
 err=c.SaveUploadedFile(file,fmt.Sprintf("./images/%s",image))
 if err!=nil {
 c.JSON(http.StatusBadRequest, gin.H{
	"fail upload",
 })
 }
 imageUrl:=fmt.Sprintf("http://localhost:3000/images/%s",image)
 data:=map[string]interface{}{
	"imageName":image,
	"imageUrl":imageUrl,
	"header":file.Header,
	"size":file.size,
 }
 c.JSON(http.StatusOK, gin.H{})
}
