/**
 * radius-guard: blocks Radius (radius.pi.dev), Earendil Works' hosted service for pi.
 *
 * Radius is a model provider, the /share upload target, and, after a Radius sign-in, an MCP server that pi offers to
 * add. pi lets an extension's `oauth` replace a built-in provider's, so this extension registers "radius" with no
 * models and an oauth that refuses `/login radius` and turns a stored sign-in into an empty credential. With no
 * credential, pi lists no Radius models and /share does not upload to Radius.
 *
 * A refresh must not throw: /share awaits the Radius credential outside its own try, so a throw on an expired
 * sign-in crashes pi. It returns a dead sign-in (empty tokens, valid for a year, because pi refuses a refreshed token
 * that expires within five minutes), which pi saves over the stored one.
 *
 * The oauth override cannot touch a Radius API key saved with /login, so session start warns while pi has one.
 * bin/pi-bridge unsets RADIUS_API_KEY and points PI_RADIUS_GATEWAY (used by /bug uploads) at a closed local port.
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

const NAME = "Radius (blocked in pi-bridge)";
const REFUSED = "Radius is blocked in pi-bridge";
const DEAD_SIGNIN_MS = 365 * 24 * 60 * 60 * 1000;
const KEY_CHECK_MS = 3000;

async function radiusKeyWarning(ctx: ExtensionContext): Promise<string | undefined> {
	const registry = ctx.modelRegistry as unknown as { getApiKeyForProvider?: (id: string) => Promise<string | undefined> } | undefined;
	if (typeof registry?.getApiKeyForProvider !== "function") return undefined;
	const key = await Promise.race([
		registry.getApiKeyForProvider("radius"),
		new Promise<undefined>((resolve) => setTimeout(resolve, KEY_CHECK_MS).unref?.()),
	]);
	if (typeof key !== "string" || key === "") return undefined;
	return `pi has a Radius API key, so /share can upload this session to radius.pi.dev. Run /logout and remove "${NAME}", or unset RADIUS_API_KEY.`;
}

export default function (pi: ExtensionAPI) {
	try {
		pi.registerProvider("radius", {
			name: NAME,
			models: [],
			oauth: {
				name: NAME,
				login: async (): Promise<never> => {
					throw new Error(REFUSED);
				},
				refreshToken: async () => ({ access: "", refresh: "", expires: Date.now() + DEAD_SIGNIN_MS }),
				getApiKey: () => "",
			},
		});
	} catch (err) {
		pi.on("session_start", (_event, ctx) => {
			ctx.ui.notify(`radius-guard could not block Radius: ${err instanceof Error ? err.message : String(err)}`, "error");
		});
		return;
	}
	pi.on("session_start", async (_event, ctx) => {
		try {
			const warning = await radiusKeyWarning(ctx);
			if (warning) ctx.ui.notify(warning, "error");
		} catch {
			/* the check is best effort */
		}
	});
}
