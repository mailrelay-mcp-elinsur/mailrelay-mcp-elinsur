import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import { GitHubHandler } from "./github-handler";

type Props = {
	login: string;
	name: string | null;
	email: string | null;
	accessToken: string;
};

const MAILRELAY_API_BASE = "https://elinsur.ipzmarketing.com/api/v1";
const ALLOWED_GITHUB_LOGIN = "mailrelay-mcp-elinsur";

async function mailrelayGet(env: Env, path: string) {
	const response = await fetch(`${MAILRELAY_API_BASE}${path}`, {
		headers: {
			"X-AUTH-TOKEN": env.MAILRELAY_API_TOKEN,
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

export class MyMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "Mailrelay Elinsur",
		version: "0.1.0",
	});

	async init() {
		if (this.props?.login !== ALLOWED_GITHUB_LOGIN) {
			throw new Error("Usuario de GitHub no autorizado para Mailrelay Elinsur");
		}

		this.server.tool(
			"listar_grupos",
			"Lista los grupos de Mailrelay de Elinsur con su ID, nombre y cantidad de suscriptores.",
			{},
			async () => {
				const data = await mailrelayGet(this.env, "/groups");
				return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
			},
		);

		this.server.tool(
			"listar_suscriptores",
			"Lista suscriptores de Mailrelay de Elinsur. Es solo lectura.",
			{
				page: z.number().int().min(1).default(1),
				per_page: z.number().int().min(1).max(100).default(30),
			},
			async ({ page, per_page }) => {
				const params = new URLSearchParams({
					page: String(page),
					per_page: String(per_page),
				});
				const data = await mailrelayGet(this.env, `/subscribers?${params.toString()}`);
				return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
			},
		);
	}
}

export default new OAuthProvider({
	apiHandler: MyMCP.serve("/mcp"),
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: GitHubHandler as any,
	tokenEndpoint: "/token",
});
