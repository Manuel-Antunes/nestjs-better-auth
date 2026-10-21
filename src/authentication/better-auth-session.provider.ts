import { type ExecutionContext, Inject, Injectable } from "@nestjs/common";
import {
	AuthenticationProvider,
	AuthenticationRegistry,
	type AuthenticationResult,
} from "@nestjs/authentication";
import { fromNodeHeaders } from "better-auth/node";
import {
	type AuthModuleOptions,
	MODULE_OPTIONS_TOKEN,
} from "../auth-module-definition.ts";
import { AuthService } from "../auth-service.ts";
import type { BetterAuthSession, BetterAuthUser } from "../types.ts";
import { getRequestFromContext } from "../utils.ts";

/**
 * Authenticates with Better Auth's session: the session cookie, and a Bearer
 * token too when the `bearer()` plugin is enabled, because `getSession()`
 * reads both.
 *
 * Registers itself in `AuthenticationRegistry`, so `@nestjs/authentication`'s
 * guard, decorators and `AuthenticationContext` work as the Nest docs describe.
 */
@Injectable()
export class BetterAuthSessionProvider extends AuthenticationProvider<
	BetterAuthUser,
	BetterAuthSession
> {
	constructor(
		@Inject(AuthService) private readonly authService: AuthService,
		@Inject(MODULE_OPTIONS_TOKEN) options: AuthModuleOptions,
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		registry.registerProvider(this, {
			order: options.providerOrder?.session ?? 0,
		});
	}

	async authenticate(
		context: ExecutionContext,
	): Promise<AuthenticationResult<BetterAuthUser, BetterAuthSession> | null> {
		const request = await getRequestFromContext(context);
		const result = await this.authService.api.getSession({
			headers: fromNodeHeaders(
				request?.headers || request?.handshake?.headers || [],
			),
		});
		// No credentials this provider understands: the guard tries the next one.
		if (!result) return null;

		return {
			user: result.user as BetterAuthUser,
			session: result.session as BetterAuthSession,
			// Better Auth issues no session until the second factor passes, so a
			// session whose user has 2FA enabled has passed it. This is what makes
			// @Authenticate({ mfa: true }) work.
			mfa: (result.user as { twoFactorEnabled?: boolean }).twoFactorEnabled
				? "verified"
				: undefined,
		};
	}

	challenge(): string {
		return "Cookie";
	}
}
