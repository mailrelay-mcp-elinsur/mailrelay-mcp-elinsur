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

function requireAuthorizedUser() {
	const auth = getMcpAuthContext();
	const login = auth?.props?.login;
	if (login !== ALLOWED_GITHUB_LOGIN) {
		throw new Error("Usuario de GitHub no autorizado para Mailrelay Elinsur");
	}
	return String(login);
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
			const login = requireAuthorizedUser();
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
			requireAuthorizedUser();
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
			requireAuthorizedUser();
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

export default new OAuthProvider({
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
