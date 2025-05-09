-- +goose Up
CREATE TABLE users(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    email TEXT NOT NULL,
    UNIQUE(email)
);

CREATE TABLE chirps(
    id UUID PRIMARY KEY,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    body TEXT NOT NULL,
    user_id UUID NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE 
);

-- +goose Down
DROP TABLE chirps;
DROP TABLE users;
