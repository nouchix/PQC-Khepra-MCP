# ASAF Runtime Adapter Fabric v0.1

## Objective

Provide infrastructure portability while keeping ASAF Proof Plane independent from execution providers.

## Model

```
ASAF Control Plane
        |
RuntimeProvider Interface
        |
+---------+----------+----------+
|         |          |
Docker   ECS   Kubernetes   Railway Adapter
```

## Runtime Provider Contract

Providers implement:

- deploy
- start
- stop
- restart
- logs
- metrics
- lifecycle events

## Principle

Runtime executes. ASAF proves.

Infrastructure is replaceable; evidence remains portable.
