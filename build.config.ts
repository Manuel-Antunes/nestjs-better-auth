import { defineBuildConfig } from "unbuild";

export default defineBuildConfig({
	declaration: true,
	entries: ["src/index", "src/authentication/index", "src/authorization/index"],
	rollup: {
		emitCJS: false,
		esbuild: {
			tsconfigRaw: {
				compilerOptions: {
					experimentalDecorators: true,
				},
			},
		},
	},
});
