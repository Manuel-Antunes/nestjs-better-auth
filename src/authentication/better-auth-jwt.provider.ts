import { type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import {
	AuthenticationError,
	AuthenticationProvider,
	AuthenticationRegistry,
	type AuthenticationResult,
} from "@nestjs/authentication";
import {
	type AuthModuleOptions,
	MODULE_OPTIONS_TOKEN,
} from "../auth-module-definition.ts";
import { AuthService } from "../auth-service.ts";
import type { BetterAuthUser } from "../types.ts";
import { hasPlugin } from "./utils.ts";

const JWT_PATTERN = /^[\w-]+\.[\w-]+\.[\w-]+$/;

/** The claims of a verified JWT, as `@CurrentSession()` sees them. */
export type BetterAuthJwtClaims = {
	sub: string;
	aud: string;
	[claim: string]: unknown;
};

/**
 * Authenticates `Authorization: Bearer <jwt>` for services that receive the
 * JWT Better Auth's `jwt()` plugin issues (`/token`, `set-auth-jwt`), verified
 * with the plugin's JWKS. Registers itself only when the `jwt` plugin is
 * configured.
 *
 * Tokens that are not shaped like a JWT (no two dots) are left to the other
 * providers, the convention Nest uses so that JWT and API key providers can
 * coexist.
 */
@Injectable()
export class BetterAuthJwtProvider extends AuthenticationProvider<
	BetterAuthUser,
	BetterAuthJwtClaims
> {
	constructor(
		@Inject(AuthService) private readonly authService: AuthService,
		@Inject(MODULE_OPTIONS_TOKEN) options: AuthModuleOptions,
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		if (hasPlugin(options.auth, "jwt")) {
			registry.registerProvider(this, {
				order: options.providerOrder?.jwt ?? 1,
			});
		}
	}

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthJwtClaims> | null> {
		const authorization = this.header(context, "authorization");
		const match = authorization && /^Bearer\s+(\S+)$/i.exec(authorization);
		const token = match?.[1];
		if (!token || !JWT_PATTERN.test(token)) return null;

		// biome-ignore lint/suspicious/noExplicitAny: the API only exists with the jwt plugin
		const api = this.authService.api as any;
		let payload: BetterAuthJwtClaims | null = null;
		try {
			payload = (await api.verifyJWT({ body: { token } }))?.payload ?? null;
		} catch {
			payload = null;
		}
		if (!payload?.sub) throw this.invalid("invalid token");

		const ctx = await this.authService.instance.$context;
		const user = await ctx.internalAdapter.findUserById(payload.sub);
		if (!user) throw this.invalid("invalid token");

		return { user: user as BetterAuthUser, session: payload };
	}

	challenge(): string {
		return 'Bearer realm="api"';
	}

	private invalid(description: string): AuthenticationError {
		return new AuthenticationError(description, {
			code: "invalid_token",
			challenge: `Bearer realm="api", error="invalid_token", error_description="${description}"`,
		});
	}
}
