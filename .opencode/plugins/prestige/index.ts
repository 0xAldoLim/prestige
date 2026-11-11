import { Plugin } from "@opencode/plugin"
import path from "node:path"

export default Plugin.define({
  id: "prestige",
  async setup(ctx) {
    const projectDir = ctx.location.project?.canonical ?? ctx.location.directory
    if (!projectDir) {
      console.warn("[prestige] No project directory available; skipping MCP registration.")
      return
    }

    const options = (ctx.options ?? {}) as Record<string, unknown>
    const python = typeof options.python === "string" ? options.python : "python"
    const home = process.env.PRESTIGE_HOME || (typeof options.home === "string"
      ? options.home
      : path.join(projectDir, ".prestige"))
    const extraEnv =
      options.env && typeof options.env === "object"
        ? (options.env as Record<string, string>)
        : {}

    await ctx.mcp.transform((editor) => {
      editor.set("prestige", {
        type: "local",
        command: [python, "-m", "prestige", "agent"],
        cwd: projectDir,
        environment: {
          PATH: process.env.PATH ?? "",
          PRESTIGE_HOME: home,
          PRESTIGE_REMOTE_ENABLED: process.env.PRESTIGE_REMOTE_ENABLED ?? "",
          PRESTIGE_RESEARCH_ENABLED: process.env.PRESTIGE_RESEARCH_ENABLED ?? "",
          ...extraEnv,
        },
        disabled: false,
      } as any)
    })

  },
})
