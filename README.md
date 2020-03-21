IPC based simulator of P2P network
==================================

Developed for a purpose of my researches on distributed networks. Written on ANSI C.

build:
------

```
sudo apt install libsqlite3-dev libbase58-dev libsodium-dev libev-dev libssl-dev
make
```

tests:
------

Format of test string: t-[proto][mode]-[next]-[prev]-[peers]

sample:

```
make t-udps-1-1-10
```

result log is "main.log".

clean:
------

To remove all sqlite3 database files and other temporary stuff:

```
make clean
```
