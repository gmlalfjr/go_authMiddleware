package auth

import (
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	commonResponse "github.com/gmlalfjr/go_CommonResponse/utils"
)

func VerifyAuthorization(c *gin.Context) {

	getHeader := c.GetHeader("Authorization")
	if len(getHeader) <= 0 {
		c.JSON(http.StatusBadRequest, commonResponse.NewBadRequest("Bad request"))
		c.Abort()
		return
	}
	if !strings.Contains(getHeader, "Bearer") {
		c.JSON(http.StatusBadRequest, commonResponse.ForbiddenError("Invalid Token"))
		c.Abort()
		return
	}
	tokenString := strings.Replace(getHeader, "Bearer ", "", -1)
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("accessToken"), nil
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, commonResponse.ForbiddenError("Token Expired"))
		c.Abort()
		return
	}

	for key, val := range claims {
		c.Set(key, val)
	}
	c.Next()
}
