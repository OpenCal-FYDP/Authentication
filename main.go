package Authorization

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/twitchtv/twirp"
	"net/http"
	"strings"
)

const (
	headerKey    = "Authorization"
	contextKey   = "token"
	headerPrefix = "Bearer "

	EmailKey = "email"
)

var (
	UnknownMethodName          = errors.New("unknown method name in TWIRP Context")
	InvalidAuthorizationHeader = errors.New("invalid authorization header in request")
	InvalidSigningMethodError  = errors.New("invalid JWT Token signing method")
)

func validateToken(parsedToken *jwt.Token) (jwt.MapClaims, bool) {
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		return claims, true
	}
	return nil, false
}

func verifyToken(ctx context.Context, next twirp.Method, req interface{}, keyFunc jwt.Keyfunc) (interface{}, error) {
	if token := ctx.Value(contextKey); token == nil {
		return nil, InvalidAuthorizationHeader
	} else {
		if parsedToken, err := jwt.Parse(token.(string), keyFunc); err != nil {
			return nil, err
		} else {
			if claims, ok := validateToken(parsedToken); ok {
				ctx = context.WithValue(ctx, EmailKey, claims["sub"])
				return next(ctx, req)
			} else {
				return nil, InvalidAuthorizationHeader
			}
		}
	}
}

func WithJWT(base http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		tokenString := r.Header.Get(headerKey)
		tokenString = strings.TrimPrefix(tokenString, headerPrefix)
		ctx = context.WithValue(ctx, contextKey, tokenString)
		r = r.WithContext(ctx)
		base.ServeHTTP(w, r)
	})
}

func NewAuthorizationInterceptor(secret []byte, methodNames ...string) twirp.Interceptor {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, InvalidSigningMethodError
		}
		return secret, nil
	}
	return func(next twirp.Method) twirp.Method {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			if len(methodNames) == 0 {
				return verifyToken(ctx, next, req, keyFunc)
			} else {
				if methodName, ok := twirp.MethodName(ctx); !ok {
					return nil, UnknownMethodName
				} else {
					for _, method := range methodNames {
						if methodName == method {
							return verifyToken(ctx, next, req, keyFunc)
						}
					}
					return next(ctx, req)
				}
			}
		}
	}
}
