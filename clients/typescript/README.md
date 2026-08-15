# @brandonrc/mobula-client

Generated TypeScript client for the Mobula control-plane API. **The source
of truth is [`openapi.json`](../../openapi.json)** at the repo root, which
CI drift-guards against the Rust code — this package is regenerated from it
and published to the GitHub Packages npm registry on every `v*` tag.

Consumers (e.g. `mobula-ui`) never hand-write API types or point a codegen
tool at a running server; they depend on this package.

## Install

It's published to GitHub Packages, so scope the registry in `.npmrc`:

```
@brandonrc:registry=https://npm.pkg.github.com
```

(For local dev / CI, authenticate with a GitHub token that has
`read:packages`: `//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}`.)

```bash
npm install @brandonrc/mobula-client
```

## Use

```ts
import { createMobulaClient, type ClusterView } from "@brandonrc/mobula-client";

const mobula = createMobulaClient({
  baseUrl: "https://mobula.example.com",
  token: userJwt,
});

const { data, error } = await mobula.GET("/api/v1/clusters");
// `data` is ClusterView[]; every path/body/response is type-checked
// against the schema, so API drift is a compile error.
```

Type-only imports (`ClusterView`, `CreateCluster`, `ServiceSpec`, …) are
also exported if you keep your own fetch layer.
