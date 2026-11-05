package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/PedroTamburini/hexago/internal/core/domain/entity"
	domainerr "github.com/PedroTamburini/hexago/internal/core/domain/error"
	portout "github.com/PedroTamburini/hexago/internal/core/port/secondary"
)

type stubCredentialsRepository struct {
	credentials *portout.Credentials
	err         error
	calledWith  string
	calls       int

	credentialsByID    *portout.Credentials
	credentialsByIDErr error

	updatedPasswordID   uint64
	updatedPasswordHash string
	updatePasswordCalls int
	updatePasswordErr   error

	tempPasswordID        uint64
	tempPasswordHash      string
	tempPasswordExpiresAt time.Time
	tempPasswordCalls     int
	tempPasswordErr       error
}

func (s *stubCredentialsRepository) FindCredentialsByUsername(_ context.Context, username string) (*portout.Credentials, error) {
	s.calls++
	s.calledWith = username

	if s.err != nil {
		return nil, s.err
	}

	return s.credentials, nil
}

func (s *stubCredentialsRepository) FindCredentialsByID(context.Context, uint64) (*portout.Credentials, error) {
	if s.credentialsByIDErr != nil {
		return nil, s.credentialsByIDErr
	}

	if s.credentialsByID != nil {
		return s.credentialsByID, nil
	}

	return s.credentials, nil
}

func (s *stubCredentialsRepository) UpdatePasswordAndClearTemp(_ context.Context, id uint64, passwordHash string) error {
	s.updatePasswordCalls++
	s.updatedPasswordID = id
	s.updatedPasswordHash = passwordHash

	return s.updatePasswordErr
}

func (s *stubCredentialsRepository) SetTempPassword(_ context.Context, id uint64, passwordHash string, expiresAt time.Time) error {
	s.tempPasswordCalls++
	s.tempPasswordID = id
	s.tempPasswordHash = passwordHash
	s.tempPasswordExpiresAt = expiresAt

	return s.tempPasswordErr
}

type stubPasswordHasher struct {
	hash          string
	expectedPlain string
	hashes        int
	compares      int
	comparedHash  string
}

func (s *stubPasswordHasher) Hash(string) (string, error) {
	s.hashes++

	return s.hash, nil
}

func (s *stubPasswordHasher) Compare(hashed, plain string) error {
	s.compares++
	s.comparedHash = hashed

	if hashed != s.hash || plain != s.expectedPlain {
		return errors.New("invalid password")
	}

	return nil
}

type stubJWTService struct {
	generatedFor     uint64
	generatedVer     int
	generatedPurpose string
	generations      int
	tokenClaims      *portout.TokenClaims
	parseErr         error
}

func (s *stubJWTService) GenerateToken(userID uint64, tokenVersion int) (string, error) {
	return s.GenerateTokenWithPurpose(userID, tokenVersion, portout.TokenPurposeAccess)
}

func (s *stubJWTService) GenerateTokenWithPurpose(userID uint64, tokenVersion int, purpose string) (string, error) {
	s.generatedFor = userID
	s.generatedVer = tokenVersion
	s.generatedPurpose = purpose
	s.generations++

	return "generated-token", nil
}

func (s *stubJWTService) ExpireSeconds() int64 { return 900 }

func (s *stubJWTService) ValidateToken(string) (uint64, error) { return 0, nil }

func (s *stubJWTService) ParseClaims(string) (*portout.TokenClaims, error) {
	if s.parseErr != nil {
		return nil, s.parseErr
	}

	if s.tokenClaims != nil {
		return s.tokenClaims, nil
	}

	return &portout.TokenClaims{
		JTI:      "generated-jti",
		Subject:  "1",
		IssuedAt: time.Now(),
	}, nil
}

type stubDenylist struct {
	revoked     map[string]time.Time
	revokeCalls int
	err         error
}

func (s *stubDenylist) Revoke(_ context.Context, jti string, expiresAt time.Time) error {
	s.revokeCalls++
	if s.err != nil {
		return s.err
	}
	if s.revoked == nil {
		s.revoked = make(map[string]time.Time)
	}
	s.revoked[jti] = expiresAt

	return nil
}

func (s *stubDenylist) IsRevoked(_ context.Context, jti string) (bool, error) {
	_, ok := s.revoked[jti]
	return ok, s.err
}

type stubSessionRegistry struct {
	sessions     map[string]portout.Session
	removeCalls  int
	removedAll   []uint64
	err          error
	registerCall int
}

func (s *stubSessionRegistry) Register(_ context.Context, session portout.Session) error {
	s.registerCall++
	if s.sessions == nil {
		s.sessions = make(map[string]portout.Session)
	}
	s.sessions[session.JTI] = session

	return s.err
}

func (s *stubSessionRegistry) GetByJTI(_ context.Context, jti string) (*portout.Session, error) {
	if s.err != nil {
		return nil, s.err
	}
	session, ok := s.sessions[jti]
	if !ok {
		return nil, domainerr.ErrSessionNotFound
	}

	return &session, nil
}

func (s *stubSessionRegistry) ListByUserID(_ context.Context, userID uint64) ([]*portout.Session, error) {
	if s.err != nil {
		return nil, s.err
	}

	sessions := make([]*portout.Session, 0)
	for _, session := range s.sessions {
		if session.UserID == userID {
			copied := session
			sessions = append(sessions, &copied)
		}
	}

	return sessions, nil
}

func (s *stubSessionRegistry) Remove(_ context.Context, jti string) error {
	s.removeCalls++
	delete(s.sessions, jti)

	return s.err
}

func (s *stubSessionRegistry) RemoveAllByUserID(_ context.Context, userID uint64) error {
	s.removedAll = append(s.removedAll, userID)

	return s.err
}

type stubTokenVersionManager struct {
	version  int
	increase int
	err      error
}

func (s *stubTokenVersionManager) GetVersion(context.Context, uint64) (int, error) {
	return s.version, s.err
}

func (s *stubTokenVersionManager) IncrementVersion(context.Context, uint64) (int, error) {
	s.increase++
	s.version++

	return s.version, s.err
}

type stubUserRepository struct {
	users  []*entity.User
	limit  int
	offset int

	findByID    *entity.User
	findByIDErr error

	deletedID   uint64
	deleteCalls int

	statusID     uint64
	statusActive bool
	statusCalls  int
	statusErr    error
}

func (s *stubUserRepository) Create(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) FindByID(context.Context, uint64) (*entity.User, error) {
	return s.findByID, s.findByIDErr
}

func (s *stubUserRepository) FindAll(_ context.Context, limit, offset int) ([]*entity.User, error) {
	s.limit = limit
	s.offset = offset

	return s.users, nil
}

func (s *stubUserRepository) Update(context.Context, *entity.User) error { return nil }

func (s *stubUserRepository) Delete(_ context.Context, id uint64) error {
	s.deleteCalls++
	s.deletedID = id

	return nil
}

func (s *stubUserRepository) SetStatus(_ context.Context, id uint64, isActive bool) error {
	s.statusCalls++
	s.statusID = id
	s.statusActive = isActive

	return s.statusErr
}

type stubRoleRepository struct {
	role    *entity.Role
	roleErr error

	hasRole     bool
	hasRoleErr  error
	hasRoleCall int

	assignedUserID uint64
	assignedRoleID uint64
	assignCalls    int
	assignErr      error

	removedUserID uint64
	removedRoleID uint64
	removeCalls   int
	removeErr     error

	isAdmin    bool
	isAdminErr error

	activeAdmins    int64
	activeAdminsErr error
}

func (s *stubRoleRepository) FindRoleByID(context.Context, uint64) (*entity.Role, error) {
	if s.roleErr != nil {
		return nil, s.roleErr
	}

	if s.role != nil {
		return s.role, nil
	}

	return &entity.Role{ID: 1, Name: "admin"}, nil
}

func (s *stubRoleRepository) HasRole(context.Context, uint64, uint64) (bool, error) {
	s.hasRoleCall++

	return s.hasRole, s.hasRoleErr
}

func (s *stubRoleRepository) AssignRole(_ context.Context, userID, roleID uint64) error {
	s.assignCalls++
	s.assignedUserID = userID
	s.assignedRoleID = roleID

	return s.assignErr
}

func (s *stubRoleRepository) RemoveRole(_ context.Context, userID, roleID uint64) error {
	s.removeCalls++
	s.removedUserID = userID
	s.removedRoleID = roleID

	return s.removeErr
}

func (s *stubRoleRepository) IsAdmin(context.Context, uint64) (bool, error) {
	return s.isAdmin, s.isAdminErr
}

func (s *stubRoleRepository) CountActiveAdmins(context.Context) (int64, error) {
	return s.activeAdmins, s.activeAdminsErr
}
