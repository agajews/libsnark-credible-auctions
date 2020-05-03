# libsnark credible auctions

To try out the docker container, clone this repository and download the submodules:
```
git clone https://github.com/agajews/libsnark-credible-auctions.git
git submodule update --init --recursive
```

Then you can build the docker container and run it:
```
docker build -t libsnark-credible-auctions .
docker run libsnark-credible-auctions
```

When you make changes to the test file (at `src/test.cpp`), just rebuild and rerun the docker container with the above commands.
