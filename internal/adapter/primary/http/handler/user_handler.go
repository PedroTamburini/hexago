package handler

import (
	"errors"
	"net/http"

	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/controller"
	"github.com/PedroTamburini/hexago/internal/adapter/primary/http/request"
	domainerr "github.com/PedroTamburini/hexago/internal/domain/error"
	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	controller *controller.UserController
}

func NewUserHandler(controller *controller.UserController) *UserHandler {
	return &UserHandler{controller: controller}
}

func (h *UserHandler) Register(router *gin.RouterGroup) {
	router.POST("", h.Create)
	router.GET("/:id", h.Get)
	router.GET("", h.List)
	router.PUT("/:id", h.Update)
	router.DELETE("/:id", h.Delete)
}

func (h *UserHandler) Create(ctx *gin.Context) {
	var body request.CreateUserBodyRequest

	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	resp, err := h.controller.Create(ctx.Request.Context(), body)
	if err != nil {
		switch {
		case errors.Is(err, domainerr.ErrInvalidName):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid name",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidUsername):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid username",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidEmail):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid email",
			})
			return

		case errors.Is(err, domainerr.ErrUserAlreadyExists):
			ctx.JSON(http.StatusConflict, gin.H{
				"error": "user already exists",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	ctx.JSON(http.StatusCreated, resp)
}

func (h *UserHandler) Get(ctx *gin.Context) {
	var uri request.FindUserByIDUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid param",
		})
		return
	}

	resp, err := h.controller.FindByID(ctx.Request.Context(), uri)
	if err != nil {
		if errors.Is(err, domainerr.ErrUserNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (h *UserHandler) List(ctx *gin.Context) {
	var query request.FindAllUsersQuery
	if err := ctx.ShouldBindQuery(&query); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid query",
		})
		return
	}

	resp, err := h.controller.FindAll(ctx.Request.Context(), query)
	if err != nil {
		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
	}

	ctx.JSON(http.StatusOK, resp)
}

func (h *UserHandler) Update(ctx *gin.Context) {
	var uri request.UpdateUserUriRequest
	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid param",
		})
		return
	}

	var body request.UpdateUserBodyRequest
	if err := ctx.ShouldBindJSON(&body); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	resp, err := h.controller.Update(ctx.Request.Context(), uri, body)
	if err != nil {
		switch {
		case errors.Is(err, domainerr.ErrUserNotFound):
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidName):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid name",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidUsername):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid username",
			})
			return

		case errors.Is(err, domainerr.ErrInvalidEmail):
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": "invalid email",
			})
			return

		case errors.Is(err, domainerr.ErrUserAlreadyExists):
			ctx.JSON(http.StatusConflict, gin.H{
				"error": "user already exists",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	ctx.JSON(http.StatusOK, resp)
}

func (h *UserHandler) Delete(ctx *gin.Context) {
	var uri request.DeleteUserUriRequest

	if err := ctx.ShouldBindUri(&uri); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid param",
		})
		return
	}

	err := h.controller.Delete(ctx.Request.Context(), uri)
	if err != nil {
		if errors.Is(err, domainerr.ErrUserNotFound) {
			ctx.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return
		}

		_ = ctx.Error(err)
		ctx.JSON(http.StatusInternalServerError, gin.H{
			"error": "internal server error",
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"info": "user deleted successfully",
	})
}
