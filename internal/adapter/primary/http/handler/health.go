package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Health reports that the process is up. It is registered outside the versioned
// API and without authentication so orchestrators (and the Docker healthcheck)
// can probe it without credentials.
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
