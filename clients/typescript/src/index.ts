// Generated TypeScript client for the Mobula control-plane API.
//
// The source of truth is mobula's committed `openapi.json` (CI drift-guards
// it against the Rust code). `schema.d.ts` is generated from it by
// `npm run generate` (openapi-typescript) and is NOT committed — CI
// regenerates it before publishing this package to GitHub Packages.

import createClient, { type Client } from "openapi-fetch";
import type { paths, components } from "./schema";

export type { paths, components };

/** Schema type aliases so consumers import `ClusterView`, not the deep path. */
export type ClusterState = components["schemas"]["ClusterState"];
export type ClusterSpec = components["schemas"]["ClusterSpec"];
export type WorkerGroup = components["schemas"]["WorkerGroup"];
export type ClusterView = components["schemas"]["ClusterView"];
export type CreateCluster = components["schemas"]["CreateCluster"];
export type ServiceSpec = components["schemas"]["ServiceSpec"];
export type ServiceView = components["schemas"]["ServiceView"];
export type DeployService = components["schemas"]["DeployService"];
export type UpgradeStrategy = components["schemas"]["UpgradeStrategy"];
export type VersionInfo = components["schemas"]["VersionInfo"];

export interface MobulaClientOptions {
  /** Base URL of the Mobula control plane, e.g. https://mobula.example.com */
  baseUrl: string;
  /** Bearer token (OIDC JWT). Every control-plane route requires one. */
  token?: string;
  /** Extra fetch, for React Query / test injection. */
  fetch?: typeof fetch;
}

/**
 * A typed openapi-fetch client bound to the Mobula API. Every path/method/
 * body/response is checked against the published schema, so the compiler
 * catches drift the moment the API changes.
 */
export function createMobulaClient(opts: MobulaClientOptions): Client<paths> {
  const headers: Record<string, string> = {};
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  return createClient<paths>({
    baseUrl: opts.baseUrl,
    headers,
    fetch: opts.fetch,
  });
}
