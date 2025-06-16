-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3
)
RETURNING *;

-- name: GetRefreshTokenByToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;

-- name: UpdateRefreshToken :one
UPDATE refresh_tokens
SET updated_at = NOW(),
    revoked_at = $2
WHERE token = $1
RETURNING *;

