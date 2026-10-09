package port

import "context"

// PermissionChecker reports whether a user holds the given permission. It is the
// capability required by the HTTP authorization middleware.
type PermissionChecker interface {
	HasPermission(ctx context.Context, userID uint64, permission string) (bool, error)
}
