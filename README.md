# Blackswan

You probably want https://github.com/strongswan/strongswan


This is **NOT** a normal version of strongswan.
It is **HIGHLY EXPERIMENTAL** for testing virtual network devices


See https://github.com/strongswan/strongswan


## Ubuntu setup

Packages
```bash
apt install gcc autoconf libtool pkg-config gettext perl python2 flex bison yacc gperf lcov make libgmp3-dev
```

Config and build
```bash
./autogen.sh
./configure --sysconfdir=/etc
make
make install
```

Shuffle into existing installation:
```bash
cd ~/strongswan
git pull
make
make install

#pushd /usr/lib/ipsec
#cp ~/strongswan/src/libstrongswan/.libs/libstrongswan.* .

ipsec restart
```