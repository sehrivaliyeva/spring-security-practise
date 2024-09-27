-- Kullanıcılar tablosu
CREATE TABLE users (
                       username VARCHAR(50) NOT NULL PRIMARY KEY,
                       password VARCHAR(100) NOT NULL,
                       enabled BOOLEAN NOT NULL
);

-- Kullanıcı rolleri tablosu
CREATE TABLE authorities (
                             username VARCHAR(50) NOT NULL,
                             authority VARCHAR(50) NOT NULL,
                             FOREIGN KEY (username) REFERENCES users(username)
);

-- authorities.username alanına indeks ekliyoruz
CREATE UNIQUE INDEX ix_auth_username ON authorities (username, authority);