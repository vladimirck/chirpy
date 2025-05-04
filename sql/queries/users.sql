-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, hashed_password, email, is_chirpy_red)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2,
    FALSE
)
RETURNING *;

-- name: DeleteAllUsers :exec
TRUNCATE users, chirps, refresh_tokens;

-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps ORDER BY created_at;

-- name: GetChirpsByUserID :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at;

-- name: GetChirpByID :one
SELECT * FROM chirps WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: SaveRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days',
    NULL
)
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT * FROM refresh_tokens WHERE token = $1;

-- name: RevokeRefreshToken :one
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1
RETURNING *;

-- name: UpdateUserData :one
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteChirp :one
DELETE FROM chirps WHERE id = $1
RETURNING *;

-- name: UpgradeUserPlan :one
UPDATE users
SET is_chirpy_red = TRUE, updated_at = NOW()
WHERE id = $1
RETURNING *;