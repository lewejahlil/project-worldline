# Devnet

Run a local chain and deploy dev verifier + adapter + oracle.

## Start
./devnet/start.sh

## Deploy
cd devnet && forge script Deploy --rpc-url http://127.0.0.1:8545 --broadcast -vv

## Stop
./devnet/stop.sh
