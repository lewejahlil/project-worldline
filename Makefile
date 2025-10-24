.PHONY: all build test lint circuits contracts rust devnet

all: build

build: circuits contracts rust

circuits:
npm run c:ptau
npm run c:compile
npm run c:setup
npm run c:export

contracts:
npm run contracts:build

rust:
cargo build

lint:
npm run lint
npm run format:check

ci:
npm run test

