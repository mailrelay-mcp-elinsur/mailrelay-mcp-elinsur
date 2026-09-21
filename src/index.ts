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

function createServer() {
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
			securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }],
			_meta: { securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }] },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async () => {
			const login = getAuthorizedUser();
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
			securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }],
			_meta: { securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }] },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async () => {
			const login = getAuthorizedUser();
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
			securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }],
			_meta: { securitySchemes: [{ type: "oauth2", scopes: MCP_SCOPES }] },
			annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
		},
		async ({ page, per_page }) => {
			const login = getAuthorizedUser();
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

const mcpHandler = createMcpHandler(createServer);

class McpApiHandler extends WorkerEntrypoint<Env> {
	fetch(request: Request) {
		return mcpHandler(request, this.env, this.ctx);
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

export default {
	fetch(request: Request, workerEnv: Env, ctx: ExecutionContext) {
		const url = new URL(request.url);
		const hasBearer = request.headers.get("Authorization")?.startsWith("Bearer ");

		// Allow anonymous MCP discovery so ChatGPT can enumerate tools and read
		// their OAuth security metadata. Tool calls themselves return an MCP
		// authentication challenge until the user connects the app.
		if (url.pathname === "/mcp" && !hasBearer) {
			return mcpHandler(request, workerEnv, ctx);
		}

		return oauthProvider.fetch(request, workerEnv, ctx);
	},
};
