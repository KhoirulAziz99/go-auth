package authentication

import (

	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)
var jwtKey = "Sangat_rahasia"

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}


func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorization"})
			c.Abort()
			return
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) { return jwtKey, nil })

		if !token.Valid || err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorization"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("claims", claims)

		c.Next()
	}
}


func loginHandler(c *gin.Context) {
	var user User

	if err := c.ShouldBind(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println(user.Username)
	fmt.Println(user.Password)
	//logic authentication(compare username and password)
	if user.Username == "enigma" && user.Password == "12345" {
		//bikin code untuk generate token
		token := jwt.New(jwt.SigningMethodHS256)

		claims := token.Claims.(jwt.MapClaims) // ini map

		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Minute * 1).Unix() //token akan expired dalam 1 menit

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func profileHandler(c *gin.Context) {
	// Ambil username dari JWT token
	claims := c.MustGet("claims").(jwt.MapClaims)
	username := claims["username"].(string)

	// seharusnya return user  dari database , tapi di contoh ini kita pakai code block
	c.JSON(http.StatusOK, gin.H{"username": username})
}
