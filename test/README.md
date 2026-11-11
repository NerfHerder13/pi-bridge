# Tests

Run all tests with one command from the repo root (Node 22, from `~/.local/node/bin`):

```bash
node --import ./test/register.mjs --test 'test/**/*.test.ts'
```

- No `npm install` is needed. `test/register.mjs` resolves `@earendil-works/*` from `~/.local/share/pi-icr/node_modules`. Set `PI_SDK_DIR` to use another install.
- Node strips the TypeScript types itself.
- Tests drive an extension through a real pi SDK session on the faux model provider, against throwaway git repos in a temp dir.
- `test/git-guard/harness.ts` is the reusable part: `callTool({ cwd, tool, args, ui, approve })` has the model call one tool and returns the result plus every dialog the UI recorded.
- git-guard reads `SUBAGENT_STATE_DIR` (default `~/.local/state/subagent`) for the subagent worktree directory. The harness points it at a temp dir, so tests never touch the real one.
