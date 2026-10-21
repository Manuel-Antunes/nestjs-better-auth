import type { BaseUserSession } from "./auth-guard.ts";

/** The user Better Auth resolves for a request. */
export type BetterAuthUser = BaseUserSession["user"] & {
	role?: string | string[];
};

/** The session Better Auth resolves for a request. */
export type BetterAuthSession = BaseUserSession["session"] & {
	activeOrganizationId?: string | null;
};

/**
 * Types `@nestjs/authentication`'s `@CurrentUser()` / `@CurrentSession()` with
 * your Better Auth instance. Augment once per app:
 *
 * @example
 * ```ts
 * declare module '@nestjs/authentication' {
 *   interface AuthenticationTypes extends BetterAuthAuthenticationTypes<typeof auth> {}
 * }
 * ```
 */
export type BetterAuthAuthenticationTypes<T> = T extends {
	$Infer: { Session: { user: infer U; session: infer S } };
}
	? { user: U; session: S }
	: { user: BetterAuthUser; session: BetterAuthSession };
