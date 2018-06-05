Setup DEX Server
----------------
docker run -v /home/sumagant/os-proj/dex/examples:/examples --network host quay.io/coreos/dex:v2.10.0 serve /examples/config-dev.yaml

DEX example client
------------------
This is not needed, but just for reference
#https://github.com/coreos/dex/blob/master/Documentation/using-dex.md
docker run --network host dex-example-app