// Package permission defines the canonical permission names shared by the HTTP
// route guards (adapter layer) and the RBAC seed (infrastructure layer). Keeping
// them in a single place prevents silent drift: a typo in one of the two sides
// would otherwise turn into a permanent "403 Forbidden".
package permission

const (
	UsersRead   = "users:read"
	UsersCreate = "users:create"
	UsersUpdate = "users:update"
	UsersDelete = "users:delete"
)

// All returns every permission known to the application. The seed uses it to
// grant the admin role all permissions without duplicating the list.
func All() []string {
	return []string{UsersRead, UsersCreate, UsersUpdate, UsersDelete}
}
