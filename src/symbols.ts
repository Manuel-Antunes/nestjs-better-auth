export const BEFORE_HOOK_KEY = Symbol("BEFORE_HOOK") as symbol;
export const AFTER_HOOK_KEY = Symbol("AFTER_HOOK") as symbol;
export const HOOK_KEY = Symbol("HOOK") as symbol;
export const AUTH_MODULE_OPTIONS_KEY = Symbol("AUTH_MODULE_OPTIONS") as symbol;

export const DATABASE_HOOK_KEY = Symbol("DATABASE_HOOK") as symbol;
export const BEFORE_DATABASE_HOOK_KEY = Symbol(
	"BEFORE_DATABASE_HOOK",
) as symbol;
export const AFTER_DATABASE_HOOK_KEY = Symbol("AFTER_DATABASE_HOOK") as symbol;

export const BETTER_AUTH_AC_POLICY = Symbol.for(
	"nestjs-better-auth:ac-policy",
) as symbol;

/**
 * Provided by `BetterAuthAuthenticationModule`, so `AuthModule` can fail fast
 * when `authentication: 'nestjs'` is set without importing it.
 */
export const NEST_ADAPTERS_MARKER = Symbol.for(
	"nestjs-better-auth:nest-adapters",
) as symbol;
