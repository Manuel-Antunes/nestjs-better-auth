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
	private readonly trustTwoFactorEnrollment: boolean;

	constructor(
		@Inject(AuthService) private readonly authService: AuthService,
		@Inject(MODULE_OPTIONS_TOKEN) options: AuthModuleOptions,
		@Inject(AuthenticationRegistry) registry: AuthenticationRegistry,
	) {
		super();
		this.trustTwoFactorEnrollment =
			options.session?.trustTwoFactorEnrollment === true;
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
			// A session records no proof of a second factor, and `twoFactor()` only
			// challenges credential sign-ins: enrollment alone is not verification,
			// unless the app opted in knowing no other sign-in method reaches
			// these users.
			mfa:
				this.trustTwoFactorEnrollment &&
				(result.user as { twoFactorEnabled?: boolean }).twoFactorEnabled
					? "verified"
					: undefined,
		};
	}

	/** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
	challenge(): string {
		return "Cookie";
	}
}
