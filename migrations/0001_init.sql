CREATE TABLE IF NOT EXISTS ban_word (
    content TEXT
);

CREATE TABLE IF NOT EXISTS users (
    userID INTEGER PRIMARY KEY,
    violationCount INTEGER NOT NULL DEFAULT 0,
    availableUntil INTEGER
);
