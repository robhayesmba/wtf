DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS auths;
DROP TABLE IF EXISTS dial_memberships;
DROP TABLE IF EXISTS dial_values;
DROP TABLE IF EXISTS dials;
DROP TABLE IF EXISTS users;

CREATE OR REPLACE FUNCTION update_last_update_at_column()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TABLE users (
    id         SERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    email      TEXT UNIQUE,
    api_key    TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TRIGGER update_users_updatedAt BEFORE UPDATE
    ON users FOR EACH ROW EXECUTE PROCEDURE
        update_last_update_at_column();

CREATE TABLE auths (
    id            SERIAL PRIMARY KEY,
    user_id       INT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    source        TEXT NOT NULL,
    source_id     TEXT NOT NULL,
    access_token  TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expiry        TIMESTAMP,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    UNIQUE(user_id, source),  -- one source per user
    UNIQUE(source, source_id) -- one auth per source user
);

CREATE TRIGGER update_auths_updatedAt BEFORE UPDATE
    ON auths FOR EACH ROW EXECUTE PROCEDURE
    update_last_update_at_column();

CREATE TABLE dials (
    id          SERIAL PRIMARY KEY,
    user_id     INT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    invite_code TEXT UNIQUE NOT NULL,
    value       INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX dials_user_id_idx ON dials (user_id);

CREATE TRIGGER update_dials_updatedAt BEFORE UPDATE
    ON dials FOR EACH ROW EXECUTE PROCEDURE
    update_last_update_at_column();

CREATE TABLE dial_values (
    dial_id      INT NOT NULL REFERENCES dials (id) ON DELETE CASCADE,
    "timestamp"  TIMESTAMP NOT NULL, -- per-minute precision
    value        INTEGER NOT NULL,

    PRIMARY KEY (dial_id, "timestamp")
);

CREATE TABLE dial_memberships (
    id         SERIAL PRIMARY KEY,
    dial_id    INT NOT NULL REFERENCES dials (id) ON DELETE CASCADE,
    user_id    INT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    value      INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,

    UNIQUE(dial_id, user_id)
);

CREATE TRIGGER update_dial_memberships_updatedAt BEFORE UPDATE
    ON dial_memberships FOR EACH ROW EXECUTE PROCEDURE
    update_last_update_at_column();

CREATE INDEX dial_memberships_dial_id_idx ON dial_memberships (dial_id);
CREATE INDEX dial_memberships_user_id_idx ON dial_memberships (user_id);