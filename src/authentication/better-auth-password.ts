import type { PasswordHasher } from "@nestjs/authentication";
import { verifyPassword as verifyBetterAuthHash } from "better-auth/crypto";

export interface BetterAuthPasswordOptions {
	/**
	 * Keep verifying the `salt:key` hashes Better Auth wrote by default, so
	 * existing users can still sign in. @default true
	 */
	legacyHashes?: boolean;
}

/** @internal The `PasswordHasher` behind a password config, for rehash-on-sign-in. */
export const PASSWORD_HASHER = Symbol.for("nestjs-better-auth:password-hasher");

export type BetterAuthPassword = {
	hash: (password: string) => Promise<string>;
	verify: (data: { hash: string; password: string }) => Promise<boolean>;
	[PASSWORD_HASHER]?: PasswordHasher;
};

/**
 * `emailAndPassword.password` for Better Auth, backed by Nest's
 * `PasswordHasher` (scrypt at OWASP settings, constant-time checks, NFKC
 * normalization, length limits). The cost is set in one place:
 * `AuthenticationModule.forRoot({ password: { logN } })`.
 *
 * @example
 * ```ts
 * AuthModule.forRootAsync({
 *   inject: [PasswordHasher],
 *   useFactory: (hasher: PasswordHasher) => ({
 *     auth: betterAuth({ emailAndPassword: { enabled: true, password: betterAuthPassword(hasher) } }),
 *   }),
 * })
 * ```
 */
export function betterAuthPassword(
	hasher: PasswordHasher,
	{ legacyHashes = true }: BetterAuthPasswordOptions = {},
): BetterAuthPassword {
	return {
		[PASSWORD_HASHER]: hasher,
		hash: (password) => hasher.hash(password),
		verify: async ({ hash, password }) => {
			if (hash.startsWith("$scrypt$")) return hasher.verify(password, hash);
			// Hashes Better Auth wrote with its default `salt:key` format
			return legacyHashes ? verifyBetterAuthHash({ hash, password }) : false;
		},
	};
}

/** @internal How `BetterAuthAuthenticationModule` binds the placeholder. */
export const BIND_PASSWORD_HASHER = Symbol.for(
	"nestjs-better-auth:bind-password-hasher",
);

export type NestPasswordHasher = BetterAuthPassword & {
	[BIND_PASSWORD_HASHER]: (
		hasher: PasswordHasher,
		options: BetterAuthPasswordOptions,
	) => void;
};

/**
 * For `AuthModule.forRoot()`, where the `auth` instance is built before Nest
 * can inject `PasswordHasher`. Better Auth captures `password.hash`/`verify`
 * when its context is created, so they can't be patched later: this
 * placeholder is declared in the config once, and `BetterAuthAuthenticationModule`
 * binds it to the injected `PasswordHasher`.
 *
 * @example
 * ```ts
 * betterAuth({ emailAndPassword: { enabled: true, password: nestPasswordHasher() } })
 * ```
 */
export function nestPasswordHasher(
	options: BetterAuthPasswordOptions = {},
): BetterAuthPassword {
	let delegate: BetterAuthPassword | undefined;
	/** The bound delegate, or a clear error until `BetterAuthAuthenticationModule` binds it. */
	const bound = (): BetterAuthPassword => {
		if (!delegate)
			throw new Error(
				"nestPasswordHasher() is not bound yet. Import BetterAuthAuthenticationModule (and AuthenticationModule) so it can bind Nest's PasswordHasher.",
			);
		return delegate;
	};

	const placeholder: NestPasswordHasher = {
		hash: async (password) => bound().hash(password),
		verify: async (data) => bound().verify(data),
		[BIND_PASSWORD_HASHER]: (hasher, bindOptions) => {
			delegate = betterAuthPassword(hasher, { ...options, ...bindOptions });
			placeholder[PASSWORD_HASHER] = hasher;
		},
	};
	return placeholder;
}
