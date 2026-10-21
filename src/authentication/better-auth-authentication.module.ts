import { Module } from "@nestjs/common";
import { DiscoveryModule } from "@nestjs/core";
import { NEST_ADAPTERS_MARKER } from "../symbols.ts";
import { BetterAuthApiKeyProvider } from "./better-auth-api-key.provider.ts";
import { BetterAuthJwtProvider } from "./better-auth-jwt.provider.ts";
import { BetterAuthSessionProvider } from "./better-auth-session.provider.ts";
import { BetterAuthNestWiring } from "./wiring.ts";

/**
 * Plugs Better Auth into `@nestjs/authentication`: its credential providers
 * register themselves in `AuthenticationRegistry` (each plugin-based one only
 * when its plugin is configured), and the Nest handlers and `PasswordHasher`
 * are wired into Better Auth's configuration.
 *
 * Use it with `AuthModule`'s `authentication: 'nestjs'` option, after
 * `AuthenticationModule` and `AuthModule` are imported:
 *
 * @example
 * ```ts
 * imports: [
 *   AuthenticationModule.forRoot(),
 *   AuthorizationModule.forRoot(),
 *   AuthModule.forRoot({ auth, authentication: 'nestjs' }),
 *   BetterAuthAuthenticationModule,
 * ]
 * ```
 */
@Module({
	imports: [DiscoveryModule],
	providers: [
		BetterAuthSessionProvider,
		BetterAuthApiKeyProvider,
		BetterAuthJwtProvider,
		BetterAuthNestWiring,
		{ provide: NEST_ADAPTERS_MARKER, useValue: true },
	],
	exports: [
		BetterAuthSessionProvider,
		BetterAuthApiKeyProvider,
		BetterAuthJwtProvider,
	],
})
export class BetterAuthAuthenticationModule {}
