-- +goose Up
CREATE TABLE refresh_tokens(
    token TEXT PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    user_id UUID NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITHOUT TIME ZONE,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- +goose Down
DROP TABLE refresh_tokens;
