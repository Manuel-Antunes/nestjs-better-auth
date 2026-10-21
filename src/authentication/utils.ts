import type { Auth } from "../auth-module.ts";

type PluginLike = { id: string; options?: Record<string, unknown> };

/** Better Auth plugins configured on `auth`, each with its `id`. */
function plugins(auth: Auth): PluginLike[] {
	return (auth?.options?.plugins ?? []) as PluginLike[];
}

/** The configured Better Auth plugin with this `id`, if any. */
export const findPlugin = (auth: Auth, id: string): PluginLike | undefined =>
	plugins(auth).find((plugin) => plugin.id === id);

/** Whether the Better Auth plugin with this `id` is configured. */
export const hasPlugin = (auth: Auth, id: string): boolean =>
	findPlugin(auth, id) !== undefined;

/** A date `seconds` from now, for the links Better Auth hands to a callback. */
export const expiresIn = (seconds: number): Date =>
	new Date(Date.now() + seconds * 1000);

export const toArray = <T>(value: T | T[]): T[] =>
	Array.isArray(value) ? value : [value];
