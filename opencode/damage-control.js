/**
 * Damage Control Plugin for OpenCode
 *
 * Mapping from OpenCode tool names to Claude Code tool_name values:
 *   bash  -> Bash  (bash-tool-damage-control.py, field: command)
 *   write -> Write (write-tool-damage-control.py, field: file_path)
 *   edit  -> Edit  (edit-tool-damage-control.py, field: file_path)
 */

import { homedir } from "os";
import { join } from "path";

const DAMAGE_CONTROL_DIR = join(
  homedir(),
  ".config",
  "opencode",
  "plugins",
  "damage-control",
);

/**
 * Run a damage-control Python script via uv, feeding it JSON on stdin.
 * Returns true if the command/file should be BLOCKED (exit code 2),
 * false if allowed (exit code 0).
 * Throws with the stderr message if blocked.
 */
async function runDamageControl($, scriptName, toolName, toolInput) {
  const scriptPath = join(DAMAGE_CONTROL_DIR, scriptName);
  const payload = JSON.stringify({
    tool_name: toolName,
    tool_input: toolInput,
  });

  try {
    // Feed JSON via stdin; uv run handles inline script dependencies
    await $`echo ${payload} | uv run ${scriptPath}`;
    // Exit 0: allowed
    return;
  } catch (err) {
    // uv/Bun shell throws on non-zero exit codes
    const exitCode = err.exitCode ?? err.code;
    if (exitCode === 2) {
      // Exit 2: blocked - stderr contains the reason
      const reason =
        err.stderr?.toString().trim() || "Blocked by damage-control";
      throw new Error(reason);
    }
    // Exit 1 or other: script error, don't block (fail open)
    console.error(
      `[damage-control] Script error (${scriptName}):`,
      err.stderr?.toString().trim(),
    );
  }
}

export const DamageControlPlugin = async ({ $ }) => {
  return {
    "tool.execute.before": async (input, output) => {
      const tool = input.tool;

      if (tool === "bash") {
        const command = output.args?.command ?? "";
        if (!command) return;
        await runDamageControl($, "bash-tool-damage-control.py", "Bash", {
          command,
        });
      } else if (tool === "write") {
        const filePath = output.args?.filePath ?? "";
        if (!filePath) return;
        await runDamageControl($, "write-tool-damage-control.py", "Write", {
          file_path: filePath,
        });
      } else if (tool === "edit") {
        const filePath = output.args?.filePath ?? "";
        if (!filePath) return;
        await runDamageControl($, "edit-tool-damage-control.py", "Edit", {
          file_path: filePath,
        });
      }
    },
  };
};
