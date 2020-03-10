# SecMgr HA: SFDB - Simple Fast Database

Experimental distributed in-memory database based on gRPC & Raft consensus
algorithm.

## Getting Started

### Build
```
bazel build //...
```

### Run Tests
```
bazel test //...
```

### Start SFDB nodes

The provided launch3.sh script starts 3 sfdb nodes on localhost (ports 27910, 27911,
27912).

```
./sfdb/launch3.sh
```
