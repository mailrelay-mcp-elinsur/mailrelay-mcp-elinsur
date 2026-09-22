import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { env, WorkerEntrypoint } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { GitHubHandler } from "./github-handler";

const MAILRELAY_API_BASE = "https://elinsur.ipzmarketing.com/api/v1";
const MCP_ORIGIN = "https://mailrelay-mcp-elinsur.fernandomurano.workers.dev";
const MCP_RESOURCE = `${MCP_ORIGIN}/mcp`;
const MCP_SCOPES = ["mcp:read"];
const ALLOWED_GITHUB_LOGIN = "mailrelay-mcp-elinsur";

const OAUTH_CHALLENGE =
	`Bearer resource_metadata="${MCP_ORIGIN}/.well-known/oauth-protected-resource/mcp", scope="mcp:read", error="invalid_token", error_description="Authentication required to use Mailrelay Elinsur"`;

function getAuthorizedUser() {
	const auth = getMcpAuthContext();
	const login = auth?.props?.login;
	if (!login) return null;
	if (login !== ALLOWED_GITHUB_LOGIN) return false;
	return String(login);
}

function authenticationRequiredResult() {
	return {
		content: [
			{
				type: "text" as const,
				text: "Authentication required: connect Mailrelay Elinsur to continue.",
			},
		],
		isError: true,
		_meta: {
			"mcp/www_authenticate": [OAUTH_CHALLENGE],
		},
	};
}

function unauthorizedUserResult() {
	return {
		content: [
			{
				type: "text" as const,
				text: "The authenticated GitHub account is not authorized to use Mailrelay Elinsur.",
			},
		],
		isError: true,
	};
}

async function mailrelayGet(path: string) {
	const token = env.MAILRELAY_API_TOKEN;
	if (!token) {
		throw new Error("MAILRELAY_API_TOKEN todavía no está configurado en Cloudflare");
	}

	const response = await fetch(`${MAILRELAY_API_BASE}${path}`, {
		headers: {
			"X-AUTH-TOKEN": token,
			Accept: "application/json",
		},
	});

	const text = await response.text();
	if (!response.ok) {
		throw new Error(`Mailrelay API error ${response.status}: ${text}`);
	}

	try {
		return JSON.parse(text);
	} catch {
		return text;
	}
}

type ServerAccessMode = "oauth" | "internal";

function createServer(accessMode: ServerAccessMode = "oauth") {
	const toolSecuritySchemes: any[] =
		accessMode === "internal"
			? [{ type: "noauth" }]
			: [{ type: "oauth2", scopes: MCP_SCOPES }];

	const server = new McpServer({
		name: "Mailrelay Elinsur",
		version: "0.2.0",
	});

	server.registerTool(
		"estado_conexion",
		{
			title: "Estado de conexión",
			description: "Comprueba que el usuario autenticado está autorizado para usar Mailrelay Elinsur.",
			inputSchema: z.object({}),
			securitySchemes: toolSecuritySchemes,
			_meta: { securitySchemes: toolSecuritySchemes },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async () => {
			const login = accessMode === "oauth" ? getAuthorizedUser() : "internal";
			if (login === null) return authenticationRequiredResult();
			if (login === false) return unauthorizedUserResult();
			return {
				content: [
					{
						type: "text",
						text: JSON.stringify({ conectado: true, usuario_github: login }, null, 2),
					},
				],
			};
		},
	);

	server.registerTool(
		"listar_grupos",
		{
			title: "Listar grupos",
			description:
				"Lista los grupos de Mailrelay de Elinsur con su ID, nombre y cantidad de suscriptores. Solo lectura.",
			inputSchema: z.object({}),
			securitySchemes: toolSecuritySchemes,
			_meta: { securitySchemes: toolSecuritySchemes },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async () => {
			const login = accessMode === "oauth" ? getAuthorizedUser() : "internal";
			if (login === null) return authenticationRequiredResult();
			if (login === false) return unauthorizedUserResult();
			const data = await mailrelayGet("/groups");
			return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
		},
	);

	server.registerTool(
		"listar_suscriptores",
		{
			title: "Listar suscriptores",
			description: "Lista suscriptores de Mailrelay de Elinsur. Solo lectura.",
			inputSchema: z.object({
				page: z.number().int().min(1).default(1),
				per_page: z.number().int().min(1).max(100).default(30),
			}),
			securitySchemes: toolSecuritySchemes,
			_meta: { securitySchemes: toolSecuritySchemes },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async ({ page, per_page }) => {
			const login = accessMode === "oauth" ? getAuthorizedUser() : "internal";
			if (login === null) return authenticationRequiredResult();
			if (login === false) return unauthorizedUserResult();
			const params = new URLSearchParams({
				page: String(page),
				per_page: String(per_page),
			});
			const data = await mailrelayGet(`/subscribers?${params.toString()}`);
			return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
		},
	);

	return server;
}

const mcpHandler = createMcpHandler(() => createServer("oauth"));
const internalMcpHandler = createMcpHandler(() => createServer("internal"));

function addRootSecuritySchemes(payload: any) {
	const tools = payload?.result?.tools;
	if (!Array.isArray(tools)) return payload;

	for (const tool of tools) {
		if (!tool?.securitySchemes && Array.isArray(tool?._meta?.securitySchemes)) {
			tool.securitySchemes = tool._meta.securitySchemes;
		}
	}

	return payload;
}

async function mcpHandlerWithSecuritySchemes(
	request: Request,
	workerEnv: Env,
	ctx: ExecutionContext,
	handler: typeof mcpHandler = mcpHandler,
) {
	let method: string | undefined;
	try {
		const body = await request.clone().json() as { method?: string };
		method = body?.method;
	} catch {
		// Non-JSON requests are passed through unchanged.
	}

	const response = await handler(request, workerEnv, ctx);
	if (method !== "tools/list" || !response.ok) return response;

	const contentType = response.headers.get("content-type") || "";
	const headers = new Headers(response.headers);
	headers.delete("content-length");

	if (contentType.includes("text/event-stream")) {
		const text = await response.text();
		const patched = text
			.split("\n")
			.map((line) => {
				if (!line.startsWith("data: ")) return line;
				try {
					const payload = JSON.parse(line.slice(6));
					return `data: ${JSON.stringify(addRootSecuritySchemes(payload))}`;
				} catch {
					return line;
				}
			})
			.join("\n");

		return new Response(patched, {
			status: response.status,
			statusText: response.statusText,
			headers,
		});
	}

	if (contentType.includes("application/json")) {
		try {
			const payload = addRootSecuritySchemes(await response.json());
			return new Response(JSON.stringify(payload), {
				status: response.status,
				statusText: response.statusText,
				headers,
			});
		} catch {
			return response;
		}
	}

	return response;
}

class McpApiHandler extends WorkerEntrypoint<Env> {
	fetch(request: Request) {
		return mcpHandlerWithSecuritySchemes(request, this.env, this.ctx);
	}
}

const oauthProvider = new OAuthProvider({
	apiRoute: "/mcp",
	apiHandler: McpApiHandler,
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/oauth/register",
	defaultHandler: GitHubHandler as any,
	tokenEndpoint: "/oauth/token",
	scopesSupported: MCP_SCOPES,
	resourceMetadata: {
		resource: MCP_RESOURCE,
		authorization_servers: [MCP_ORIGIN],
		scopes_supported: MCP_SCOPES,
		resource_name: "Mailrelay Elinsur MCP",
	},
});

function pickDcrRequestFields(body: any) {
	return {
		client_name: body?.client_name,
		redirect_uris: body?.redirect_uris,
		grant_types: body?.grant_types,
		response_types: body?.response_types,
		token_endpoint_auth_method: body?.token_endpoint_auth_method,
		token_endpoint_auth_methods_supported: body?.token_endpoint_auth_methods_supported,
	};
}

function pickDcrResponseFields(body: any) {
	return {
		client_id: body?.client_id,
		redirect_uris: body?.redirect_uris,
		grant_types: body?.grant_types,
		response_types: body?.response_types,
		token_endpoint_auth_method: body?.token_endpoint_auth_method,
		registration_client_uri: body?.registration_client_uri,
		has_client_secret: Boolean(body?.client_secret),
		client_secret_expires_at: body?.client_secret_expires_at,
	};
}

function normalizeMcpRequestHeaders(request: Request) {
	const headers = new Headers(request.headers);
	const accept = headers.get("accept");
	const contentType = headers.get("content-type");

	if (!accept || accept.trim() === "*/*") {
		headers.set("accept", "application/json, text/event-stream");
	}

	if (
		!contentType ||
		contentType.toLowerCase().startsWith("application/octet-stream") ||
		contentType.toLowerCase().startsWith("text/octet-stream")
	) {
		headers.set("content-type", "application/json");
	}

	return new Request(request, { headers });
}

export default {
	async fetch(request: Request, workerEnv: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);

		// TEMPORARY INTERNAL/NOAUTH MODE.
		// ChatGPT probes OAuth discovery at the origin level as well as at the
		// endpoint path. Because this same workers.dev origin also hosts the OAuth
		// provider for /mcp, the presence of those metadata documents causes the
		// internal endpoint to be classified as OAuth-protected. While we validate
		// the internal read-only connector, suppress OAuth discovery on this origin.
		// The OAuth implementation remains in the codebase and can be re-enabled
		// later (ideally on a separate hostname/Worker).
		const isOAuthDiscoveryPath =
			url.pathname === "/.well-known/oauth-protected-resource" ||
			url.pathname === "/.well-known/oauth-authorization-server" ||
			url.pathname === "/.well-known/openid-configuration" ||
			url.pathname.startsWith("/.well-known/oauth-protected-resource/mcp-interno/") ||
			(
				url.pathname.startsWith("/mcp-interno/") &&
				url.pathname.includes("/.well-known/oauth-protected-resource")
			);

		if (isOAuthDiscoveryPath) {
			return new Response(null, {
				status: 404,
				headers: {
					"Cache-Control": "no-store",
					Pragma: "no-cache",
				},
			});
		}

		// Temporary internal no-OAuth endpoint for ChatGPT developer testing.
		// Access is restricted by a Cloudflare secret embedded in the path:
		// /mcp-interno/<MCP_INTERNAL_KEY>. The internal handler exposes only the
		// existing read-only tools and advertises them as noauth to ChatGPT.
		if (url.pathname.startsWith("/mcp-interno/")) {
			const suppliedKey = decodeURIComponent(
				url.pathname.slice("/mcp-interno/".length),
			);
			const internalKey = (workerEnv as any).MCP_INTERNAL_KEY as string | undefined;

			if (!internalKey || suppliedKey !== internalKey) {
				return new Response("Not Found", { status: 404 });
			}

			const rewrittenUrl = new URL(request.url);
			rewrittenUrl.pathname = "/mcp";
			const rewrittenRequest = normalizeMcpRequestHeaders(
				new Request(rewrittenUrl.toString(), request),
			);

			if (
				rewrittenRequest.method === "POST" &&
				rewrittenRequest.headers.get("content-length") === "0"
			) {
				console.log("MCP_INTERNAL_DIAGNOSTIC", JSON.stringify({
					method: null,
					route: "empty-probe",
					status: 204,
				}));
				return new Response(null, { status: 204 });
			}

			let internalMethod: string | undefined;
			if (rewrittenRequest.method === "POST") {
				try {
					const body = await rewrittenRequest.clone().json() as { method?: string };
					internalMethod = body?.method;
				} catch {
					// Let the MCP handler produce the protocol error for malformed bodies.
				}
			}

			const response = await mcpHandlerWithSecuritySchemes(
				rewrittenRequest,
				workerEnv,
				ctx,
				internalMcpHandler,
			);
			console.log("MCP_INTERNAL_DIAGNOSTIC", JSON.stringify({
				method: internalMethod ?? null,
				route: "internal-key",
				status: response.status,
			}));
			return response;
		}

		// Diagnostic-only MCP endpoint: bypass OAuthProvider so we can verify
		// initialize/tools/list independently of OAuth. The MCP handler itself
		// is mounted at /mcp, so rewrite only the request path before dispatch.
		// Tool execution still enforces authentication via each tool's own checks.
		if (url.pathname === "/mcp-debug") {
			const rewrittenUrl = new URL(request.url);
			rewrittenUrl.pathname = "/mcp";
			const rewrittenRequest = new Request(rewrittenUrl.toString(), request);
			return mcpHandlerWithSecuritySchemes(rewrittenRequest, workerEnv, ctx);
		}

		// Tool-level OAuth: unauthenticated MCP traffic reaches the MCP handler
		// so ChatGPT can initialize, list tools, and receive mcp/www_authenticate
		// from an OAuth-protected tool call. Requests that already carry a Bearer
		// token go through OAuthProvider so the token is validated and auth context
		// is populated for the tool implementation.
		if (url.pathname === "/mcp") {
			// ChatGPT's tool-scanning probe may send Accept: */* and an
			// octet-stream Content-Type. Normalize those transport headers before
			// the MCP SDK validates the request.
			const normalizedRequest = normalizeMcpRequestHeaders(request);

			const authorization = normalizedRequest.headers.get("authorization");
			const hasBearer = Boolean(authorization?.toLowerCase().startsWith("bearer "));

			// ChatGPT may first send an empty POST as a reachability/auth probe.
			// It is not an MCP JSON-RPC message, so do not send it into the MCP
			// parser (which correctly rejects an empty JSON body). A 204 keeps
			// this compatibility probe separate from real MCP traffic.
			const contentLength = normalizedRequest.headers.get("content-length");
			if (
				normalizedRequest.method === "POST" &&
				!hasBearer &&
				contentLength === "0"
			) {
				console.log("MCP_DIAGNOSTIC", JSON.stringify({
					method: null,
					route: "empty-probe",
					status: 204,
				}));
				return new Response(null, { status: 204 });
			}

			let mcpMethod: string | undefined;
			if (normalizedRequest.method === "POST") {
				try {
					const body = await normalizedRequest.clone().json() as { method?: string };
					mcpMethod = body?.method;
				} catch {
					// Empty/non-JSON probe requests are still passed to the MCP handler.
				}
			}

			if (!hasBearer) {
				const response = await mcpHandlerWithSecuritySchemes(normalizedRequest, workerEnv, ctx);
				console.log("MCP_DIAGNOSTIC", JSON.stringify({
					method: mcpMethod ?? null,
					route: "mcp-handler-no-bearer",
					status: response.status,
				}));
				return response;
			}

			const response = await oauthProvider.fetch(normalizedRequest, workerEnv, ctx);
			console.log("MCP_DIAGNOSTIC", JSON.stringify({
				method: mcpMethod ?? null,
				route: "oauth-provider-bearer",
				status: response.status,
			}));
			return response;
		}

		if (url.pathname !== "/oauth/register" || request.method !== "POST") {
			return oauthProvider.fetch(request, workerEnv, ctx);
		}

		let requestSummary: unknown = { parse_error: true };
		try {
			requestSummary = pickDcrRequestFields(await request.clone().json());
		} catch {
			// Keep the real request untouched; this is diagnostic logging only.
		}

		const response = await oauthProvider.fetch(request, workerEnv, ctx);

		let responseSummary: unknown = { parse_error: true };
		try {
			responseSummary = pickDcrResponseFields(await response.clone().json());
		} catch {
			// Do not alter the response if it is not JSON.
		}

		console.log("DCR_DIAGNOSTIC", JSON.stringify({
			request: requestSummary,
			response_status: response.status,
			response: responseSummary,
		}));

		return response;
	},
};
