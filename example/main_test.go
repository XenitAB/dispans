package main

import (
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/xenitab/dispans/server"
)

func TestAccessible(t *testing.T) {
	op := server.NewTesting(t)
	defer op.Close()

	jwksHandler, err := newKeyHandler(op.GetURL())
	if err != nil {
		return err
	}

	e := echo.New()
	e.HideBanner = true
	e.Use(middleware.Recover())
	e.Use(middleware.Secure())

	// Unauthenticated route
	e.GET("/", accessible)

	// Restricted group
	r := e.Group("/restricted")
	r.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		KeyFunc: jwksHandler.jwtKeyFunc,
	}))
	r.GET("", restricted)

	e.Start("")
}
