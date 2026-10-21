import { createParamDecorator, type ExecutionContext } from "@nestjs/common";
import { Authenticate, Public } from "@nestjs/authentication";
import { getRequestFromContext } from "../utils.ts";

/**
 * `@Public()` from `@nestjs/authentication`, under this library's old name.
 * Use it in `authentication: 'nestjs'` mode, where the legacy
 * `AllowAnonymous()` from the main entry is not read by Nest's guard.
 */
export const AllowAnonymous: typeof Public = Public;

/** `@Authenticate({ optional: true })`, under this library's old name. */
export const OptionalAuth = (): ReturnType<typeof Authenticate> =>
	Authenticate({ optional: true });

/**
 * Better Auth's `{ user, session }` for the request, or `null` for anonymous
 * callers, resolved by `@nestjs/authentication`'s guard.
 */
export const Session: ReturnType<typeof createParamDecorator> =
	createParamDecorator(
		async (_data: unknown, context: ExecutionContext): Promise<unknown> => {
			const request = await getRequestFromContext(context);
			return request?.user
				? { user: request.user, session: request.session }
				: null;
		},
	);
