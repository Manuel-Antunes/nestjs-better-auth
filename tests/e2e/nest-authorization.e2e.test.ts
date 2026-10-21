import request from "supertest";
import { Controller, Get, Param, Patch, Post } from "@nestjs/common";
import { CurrentUser, Public } from "@nestjs/authentication";
import { AuthorizationService, Can } from "@nestjs/authorization";
import { admin } from "better-auth/plugins/admin";
import { organization } from "better-auth/plugins/organization";
import {
	AuthModule,
	AuthService,
	BetterAuthAccessControl,
} from "../../src/index.ts";
import {
	BetterAuthAuthorizationModule,
	MemberHasPermission,
	OrgRoles,
	RequireActiveOrg,
	BetterAuthACPolicy,
	Roles as RolesDecorator,
	UserHasPermission,
	activeOrganization,
} from "../../src/authorization/index.ts";
import type { BetterAuthUser } from "../../src/types.ts";
import {
	createNestAuth,
	createNestModeApp,
	uniqueEmail,
} from "../shared/nest-mode.ts";
import {
	Clock,
	Roles,
	type Post as PostRecord,
	PostOrganizationPolicy,
	PostPolicy,
	ReportPolicy,
} from "../shared/nest-policies.ts";
import { betterAuth } from "better-auth";

/** Routes protected with `@Can()` and generated policies. */
@Controller("posts")
class PostsController {
	constructor(private readonly authorization: AuthorizationService) {}

	@Public()
	@Get()
	list() {
		return { posts: [] };
	}

	@Post()
	@Can(PostPolicy, "create")
	create(@CurrentUser() user: BetterAuthUser) {
		return { createdBy: user.id };
	}

	@Post("manage")
	@Can(PostPolicy, "manage")
	manage() {
		return { ok: true };
	}

	@Patch(":authorId")
	@Can.Anyone() // the record-level check below decides
	async update(
		@CurrentUser() user: BetterAuthUser,
		@Param("authorId") authorId: string,
	) {
		const post: PostRecord = { id: "1", authorId };
		await this.authorization.authorize(PostPolicy, "update", user, post);
		return { updated: true };
	}

	@Get("undeclared")
	undeclared() {
		return { ok: true };
	}

	@Get("anyone")
	@Can.Anyone()
	anyone() {
		return { ok: true };
	}

	@Get("report")
	@Can(ReportPolicy, "read")
	report() {
		return { ok: true };
	}

	@Post("org")
	@Can(PostOrganizationPolicy, "create", activeOrganization)
	createInActiveOrg() {
		return { ok: true };
	}

	@Post("org/manage")
	@Can(PostOrganizationPolicy, "manage", activeOrganization)
	manageInActiveOrg() {
		return { ok: true };
	}

	@Post("orgs/:organizationId")
	@Can(PostOrganizationPolicy, "create", (context) => [
		context.switchToHttp().getRequest().params.organizationId as string,
	])
	createInOrg(@Param("organizationId") organizationId: string) {
		return { organizationId };
	}
}

/** Routes protected with the `@Can()`-based Roles, OrgRoles and permission decorators. */
@Controller("builtin")
class BuiltInController {
	@Get("roles")
	@RolesDecorator(["admin"])
	roles() {
		return { ok: true };
	}

	@Get("active-org")
	@RequireActiveOrg()
	activeOrg() {
		return { ok: true };
	}

	@Get("org-roles")
	@OrgRoles(["owner"])
	orgRoles() {
		return { ok: true };
	}

	@Get("user-permission")
	@UserHasPermission({ permissions: { user: ["list"] } })
	userPermission() {
		return { ok: true };
	}

	@Get("member-permission")
	@MemberHasPermission({ permissions: { organization: ["update"] } })
	memberPermission() {
		return { ok: true };
	}
}

describe("nest authorization e2e: Better Auth access control policies", () => {
	let app: Awaited<ReturnType<typeof createNestModeApp>>["app"];
	let auth: ReturnType<typeof betterAuth>;

	beforeAll(async () => {
		const setup = await createNestModeApp({
			auth: null as never,
			authorization: true,
			controllers: [PostsController, BuiltInController],
			providers: [PostPolicy, PostOrganizationPolicy, ReportPolicy, Clock],
			imports: [BetterAuthAuthorizationModule],
			authModule: AuthModule.forRootAsync({
				authentication: "nestjs",
				inject: [BetterAuthAccessControl],
				useFactory: (accessControl: BetterAuthAccessControl) => {
					auth = createNestAuth({
						baseURL: "http://localhost:3000",
						plugins: [
							admin(accessControl.admin()),
							organization({
								...accessControl.organization(),
								dynamicAccessControl: { enabled: true },
							}),
						],
					}) as never;
					return { auth };
				},
			}),
		});
		app = setup.app;
	});

	afterAll(async () => {
		await app.close();
	});

	const server = () => app.getHttpServer();
	// biome-ignore lint/suspicious/noExplicitAny: plugin endpoints are not typed on the generic auth instance
	const api = () => auth.api as any;

	/** Creates a user with `role` through the admin plugin and signs them in. */
	async function userWithRole(role: string) {
		const password = "password-123456";
		const { user } = await api().createUser({
			body: { name: role, email: uniqueEmail(), password, role },
		});
		const { token } = await auth.api.signInEmail({
			body: { email: user.email, password },
		});
		return { user: user as BetterAuthUser, token: token as string };
	}

	/** Headers carrying a bearer token, for server-side API calls on behalf of a user. */
	const bearerHeaders = (token: string) =>
		new Headers({ Authorization: `Bearer ${token}` });

	describe("user scope (admin plugin)", () => {
		it("builds roles from the discovered policies, keeping Better Auth's defaults", async () => {
			const { token } = await userWithRole("admin");
			// userHasPermission on a default statement still works for the default admin role
			const result = await api().userHasPermission({
				body: { role: "admin", permissions: { user: ["list"] } },
			});
			expect(result.success).toBe(true);
			expect(token).toBeDefined();
		});

		it("answers 401 to guests", async () => {
			await request(server()).post("/posts").expect(401);
		});

		it("lets a role with the permission through, and denies the others with 403", async () => {
			const user = await userWithRole("user");
			const adminUser = await userWithRole("admin");

			await request(server())
				.post("/posts")
				.set("Authorization", `Bearer ${user.token}`)
				.expect(201);
			await request(server())
				.post("/posts/manage")
				.set("Authorization", `Bearer ${user.token}`)
				.expect(403);

			await request(server())
				.post("/posts/manage")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(201);
		});

		it("expands the wildcard to every action of the resource", async () => {
			const adminUser = await userWithRole("admin");

			for (const route of ["/posts", "/posts/manage"]) {
				await request(server())
					.post(route)
					.set("Authorization", `Bearer ${adminUser.token}`)
					.expect(201);
			}
			// 'update' is granted through 'manage'
			await request(server())
				.patch("/posts/someone-else")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(200);
		});

		it("falls back to the permission in an overridden ability", async () => {
			const user = await userWithRole("user");

			// Authors may always edit their own posts
			await request(server())
				.patch(`/posts/${user.user.id}`)
				.set("Authorization", `Bearer ${user.token}`)
				.expect(200);
			// Others' posts need the 'update' permission, which 'user' does not have
			await request(server())
				.patch("/posts/someone-else")
				.set("Authorization", `Bearer ${user.token}`)
				.expect(403);
		});

		it("works from AuthorizationService.can() with no request", async () => {
			const adminUser = await userWithRole("admin");
			const authorization = app.get(AuthorizationService);

			expect(
				await authorization.can(PostPolicy, "create", adminUser.user),
			).toBe(true);
			expect(await authorization.can(PostPolicy, "create", null)).toBe(false);
		});

		it("supports policies with their own constructor dependencies", async () => {
			const adminUser = await userWithRole("admin");
			await request(server())
				.get("/posts/report")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(200);
			expect(app.get(ReportPolicy).clock).toBeInstanceOf(Clock);
		});

		it("keeps Nest's deny-by-default for handlers without @Can()", async () => {
			const adminUser = await userWithRole("admin");

			await request(server())
				.get("/posts/undeclared")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(403);
			await request(server())
				.get("/posts/anyone")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(200);
			await request(server()).get("/posts").expect(200);
		});
	});

	/** An organization with an owner and a `member`, both with it as their active organization. */
	async function organizationWithMember() {
		const owner = await userWithRole("user");
		const member = await userWithRole("user");

		const created = await api().createOrganization({
			body: { name: "Acme", slug: `acme-${Date.now()}-${Math.random()}` },
			headers: bearerHeaders(owner.token),
		});
		await api().addMember({
			body: {
				userId: member.user.id,
				organizationId: created.id,
				role: "member",
			},
		});
		for (const who of [owner, member]) {
			await api().setActiveOrganization({
				body: { organizationId: created.id },
				headers: bearerHeaders(who.token),
			});
		}
		return { owner, member, organizationId: created.id as string };
	}

	describe("organization scope", () => {
		it("checks the member's role in the session's active organization", async () => {
			const { owner, member } = await organizationWithMember();

			await request(server())
				.post("/posts/org/manage")
				.set("Authorization", `Bearer ${owner.token}`)
				.expect(201);

			await request(server())
				.post("/posts/org")
				.set("Authorization", `Bearer ${member.token}`)
				.expect(201);
			await request(server())
				.post("/posts/org/manage")
				.set("Authorization", `Bearer ${member.token}`)
				.expect(403);
		});

		it("denies a session with no active organization", async () => {
			const { token } = await userWithRole("user");

			await request(server())
				.post("/posts/org")
				.set("Authorization", `Bearer ${token}`)
				.expect(403);
		});

		it("checks an explicit organization taken from the route", async () => {
			const { member, organizationId } = await organizationWithMember();
			const outsider = await userWithRole("user");

			await request(server())
				.post(`/posts/orgs/${organizationId}`)
				.set("Authorization", `Bearer ${member.token}`)
				.expect(201);
			await request(server())
				.post(`/posts/orgs/${organizationId}`)
				.set("Authorization", `Bearer ${outsider.token}`)
				.expect(403);
		});

		it("works from AuthorizationService.can() with an explicit organizationId", async () => {
			const { member, organizationId } = await organizationWithMember();
			const authorization = app.get(AuthorizationService);

			expect(
				await authorization.can(
					PostOrganizationPolicy,
					"create",
					member.user,
					organizationId,
				),
			).toBe(true);
			expect(
				await authorization.can(
					PostOrganizationPolicy,
					"manage",
					member.user,
					organizationId,
				),
			).toBe(false);
			expect(
				await authorization.can(
					PostOrganizationPolicy,
					"create",
					member.user,
					null,
				),
			).toBe(false);
		});

		it("honors roles stored with dynamic access control", async () => {
			const { owner, organizationId } = await organizationWithMember();
			await api().createOrgRole({
				body: {
					role: "editor",
					permission: { post: ["create"] },
					organizationId,
				},
				headers: bearerHeaders(owner.token),
			});
			const editor = await userWithRole("user");
			await api().addMember({
				body: { userId: editor.user.id, organizationId, role: "editor" },
			});
			await api().setActiveOrganization({
				body: { organizationId },
				headers: bearerHeaders(editor.token),
			});

			await request(server())
				.post("/posts/org")
				.set("Authorization", `Bearer ${editor.token}`)
				.expect(201);
			await request(server())
				.post("/posts/org/manage")
				.set("Authorization", `Bearer ${editor.token}`)
				.expect(403);
		});
	});

	describe("built-in policies behind Roles, OrgRoles, UserHasPermission and MemberHasPermission", () => {
		it("@Roles() checks user.role", async () => {
			const adminUser = await userWithRole("admin");
			const user = await userWithRole("user");

			await request(server())
				.get("/builtin/roles")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(200);
			await request(server())
				.get("/builtin/roles")
				.set("Authorization", `Bearer ${user.token}`)
				.expect(403);
			await request(server()).get("/builtin/roles").expect(401);
		});

		it("@UserHasPermission() asks Better Auth's access control", async () => {
			const adminUser = await userWithRole("admin");
			const user = await userWithRole("user");

			await request(server())
				.get("/builtin/user-permission")
				.set("Authorization", `Bearer ${adminUser.token}`)
				.expect(200);
			await request(server())
				.get("/builtin/user-permission")
				.set("Authorization", `Bearer ${user.token}`)
				.expect(403);
		});

		it("@RequireActiveOrg(), @OrgRoles() and @MemberHasPermission() read the session's active organization", async () => {
			const routes = ["active-org", "org-roles", "member-permission"];
			const owner = await userWithRole("user");
			const noOrganization = await userWithRole("user");
			// Creating an organization makes it the creator's active one.
			await api().createOrganization({
				body: { name: "Beta", slug: `beta-${Date.now()}-${Math.random()}` },
				headers: bearerHeaders(owner.token),
			});

			for (const route of routes) {
				await request(server())
					.get(`/builtin/${route}`)
					.set("Authorization", `Bearer ${owner.token}`)
					.expect(200);
				await request(server())
					.get(`/builtin/${route}`)
					.set("Authorization", `Bearer ${noOrganization.token}`)
					.expect(403);
			}
		});

		it("@OrgRoles() refuses a member whose role is not listed", async () => {
			const { member } = await organizationWithMember();

			await request(server())
				.get("/builtin/org-roles")
				.set("Authorization", `Bearer ${member.token}`)
				.expect(403);
			await request(server())
				.get("/builtin/active-org")
				.set("Authorization", `Bearer ${member.token}`)
				.expect(200);
		});
	});

	it("exposes AuthService with the plugin-built auth instance", () => {
		expect(app.get(AuthService).instance).toBe(auth);
	});
});

describe("nest authorization e2e: BetterAuthAccessControl", () => {
	const build = (providers: Array<{ metatype: unknown }>) =>
		new BetterAuthAccessControl({
			getProviders: () => providers,
			// biome-ignore lint/suspicious/noExplicitAny: a minimal DiscoveryService
		} as any);

	it("fails when two policies define the same resource and scope", () => {
		class Duplicate extends PostPolicy {}

		expect(() =>
			build([{ metatype: PostPolicy }, { metatype: Duplicate }]).admin(),
		).toThrow(/define resource 'post'/);
	});

	it("tells apart distinct classes that share a name", () => {
		const make = () =>
			class PostPolicy extends BetterAuthACPolicy<Roles, "read">({
				resource: "article",
				statements: { [Roles.ADMIN]: ["read"] },
			}) {};
		const [first, second] = [make(), make()];
		expect(first.name).toBe(second.name);

		expect(() =>
			build([{ metatype: first }, { metatype: second }]).admin(),
		).toThrow(/define resource 'article'/);
	});

	it("keeps the same policy registered in two modules", () => {
		expect(() =>
			build([{ metatype: PostPolicy }, { metatype: PostPolicy }]).admin(),
		).not.toThrow();
	});

	it("separates the user and organization scopes", () => {
		const providers = [
			{ metatype: PostPolicy },
			{ metatype: PostOrganizationPolicy },
		];
		const { roles: userRoles } = build(providers).admin();
		const { roles: orgRoles } = build(providers).organization();

		expect(userRoles.admin.statements.post).toEqual([
			"manage",
			"create",
			"update",
		]);
		expect(userRoles.user.statements.post).toEqual(["create"]);
		expect(orgRoles.owner.statements.post).toEqual([
			"manage",
			"create",
			"update",
		]);
		expect(orgRoles.member.statements.post).toEqual(["create"]);
	});

	it("can leave Better Auth's defaults out", () => {
		const { roles } = build([{ metatype: PostPolicy }]).admin({
			defaults: false,
		});
		expect(Object.keys(roles).sort()).toEqual(["admin", "user"]);
		expect(roles.admin.statements.user).toBeUndefined();
	});

	it("rejects action names Nest never treats as abilities", async () => {
		const { BetterAuthACPolicy } = await import(
			"../../src/authorization/index.ts"
		);
		expect(() =>
			BetterAuthACPolicy({
				resource: "x",
				statements: { admin: ["before"] },
			}),
		).toThrow(/reserved/);
	});
});
