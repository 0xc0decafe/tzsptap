# tzsptap
A small tool receiving [TZSP](https://en.wikipedia.org/wiki/TZSP) encapsulated data and forwarding it to a local tap interface. Very usefull for IDS systems.

## build
On linux simply do:
```
gcc -o tzsptun -Wall tzsptun.c
```

On FreeBSD do:
```
cc -o tzsptun -Wall tzsptun.c
```

## run
To run the tool check the usage:
```
# ./tzsptun 
No listen address given.
Usage: ./tzsptun [-v] -l address [-p port]

-v              : Be verbose
-l address      : the IP address to listen on
-p port         : the port to listen on [default: 37008]
-h              : Print this help
```

You need to supply at least the address the tool shall listen on.
