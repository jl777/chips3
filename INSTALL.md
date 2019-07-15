## Installing Chips (Linux):

#### Install dependencies and clone repo
```shell
cd ~
sudo apt-get update && sudo apt-get install software-properties-common autoconf git build-essential libtool libprotobuf-c-dev libgmp-dev libsqlite3-dev python python3 zip jq libevent-dev pkg-config libssl-dev libcurl4-gnutls-dev cmake -y
git clone https://github.com/jl777/chips3.git
cd chips3/
git checkout dev
```

#### Build Berkeley DB 4.8

```shell
CHIPS_ROOT=$(pwd)
BDB_PREFIX="${CHIPS_ROOT}/db4"
mkdir -p $BDB_PREFIX
wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
echo '12edc0df75bf9abd7f82f821795bcee50f42cb2e5f76a6a281b85732798364ef db-4.8.30.NC.tar.gz' | sha256sum -c
tar -xzvf db-4.8.30.NC.tar.gz
cd db-4.8.30.NC/build_unix/
../dist/configure -enable-cxx -disable-shared -with-pic -prefix=$BDB_PREFIX
make -j$(nproc)
make install 
```

#### Build Chips

```shell
cd ~/chips3
./autogen.sh
./configure LDFLAGS="-L${BDB_PREFIX}/lib/" CPPFLAGS="-I${BDB_PREFIX}/include/" -without-gui -without-miniupnpc --disable-tests --disable-bench --with-gui=no
make -j$(nproc)
```

#### Create `chips.conf` file

Create chips.conf file with random username, password, txindex and daemon turned on:
```shell
cd ~
mkdir .chips
nano .chips/chips.conf
```

Add the following lines into your `chips.conf` file

```JSON
rpcuser=chipsuser
rpcpassword=passworddrowssap
txindex=1
daemon=1
addnode=5.9.253.195
addnode=74.208.210.191
```

#### Symlinking the binaries
```shell
sudo ln -sf /home/$USER/chips3/src/chips-cli /usr/local/bin/chips-cli
sudo ln -sf /home/$USER/chips3/src/chipsd /usr/local/bin/chipsd
sudo chmod +x /usr/local/bin/chips-cli
sudo chmod +x /usr/local/bin/chipsd
```
#### Run!
```shell
chipsd
```

#### Check
```shell
chips-cli getinfo
```
