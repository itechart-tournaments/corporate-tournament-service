CREATE DATABASE corporate_tournament_service;

\c corporate_tournament_service;

CREATE TABLE accounts (
    id        	SERIAL,
    email       text UNIQUE NOT NULL,
    PRIMARY KEY(id)
);

CREATE TABLE emails_tokens (
    id        	SERIAL,
    email       text UNIQUE NOT NULL,
    token       uuid UNIQUE NOT NULL,
    exp_at		timestamp NOT NULL,
    PRIMARY KEY(id)
);