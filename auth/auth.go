package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	commonResponse "github.com/gmlalfjr/go_CommonResponse/utils"
)

func VerifyAuthorization(secret string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		getHeader := ctx.GetHeader("Authorization")
		if len(getHeader) == 0 {
			err := errors.New("authorization header is not provided")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, commonResponse.NewBadRequest(err.Error()))
			return
		}

		if !strings.Contains(getHeader, "Bearer") {
			ctx.JSON(http.StatusBadRequest, commonResponse.NewBadRequest("invalid authorization header format"))
			ctx.Abort()
			return
		}

		keyFunc := func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				ctx.JSON(http.StatusBadRequest, commonResponse.NewBadRequest("invalid Token"))
				ctx.Abort()
				// return nil, errors.New("Invalid Token")
			}
			return []byte(secret), nil
		}

		claims := jwt.MapClaims{}
		accessToken := strings.Replace(getHeader, "Bearer ", "", -1)
		_, err := jwt.ParseWithClaims(accessToken, claims, keyFunc)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, commonResponse.ForbiddenError("Token Expired"))
			ctx.Abort()
			return
		}

		for key, val := range claims {
			ctx.Set(key, val)
		}
		ctx.Next()
	}
}
