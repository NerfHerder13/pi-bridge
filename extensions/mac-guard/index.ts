/**
 * mac-guard: stops the model from deleting or overwriting macOS settings.
 *
 * It checks every `bash`, `write`, and `edit` tool call, including calls from codemode scripts and jank workers.
 * Protected places: ~/Library (preferences, keychains, Safari, Teams, Company Portal and Entra sign-in, app
 * containers), /Library (VPN clients, Intune and MDM profiles, Microsoft SSO, launch daemons), /Applications,
 * /System, /etc, /var/db, and /opt/cisco. A path is blocked when it is inside one of them or contains one
 * (`rm -rf ~`, `rm -rf ~/*`). A few cache folders are allowed (see ALLOW).
 *
 * Shell commands are parsed, not matched as text: quotes, variables, `cd`, `for` loops, globs, redirections,
 * heredocs, `$(...)`, `sudo`/`env`/`xargs` wrappers, `sh -c`, `eval`, and shell script files are followed. Settings
 * tools are checked by subcommand: defaults, security, profiles, tccutil, networksetup, launchctl,
 * systemextensionsctl, dscl, sysadminctl, diskutil, tmutil, nvram, csrutil, spctl, fdesetup, pkgutil, brew --zap,
 * jamf, PlistBuddy, plutil, and vendor uninstallers. Inline python, node, perl, ruby, swift, and osascript code is
 * blocked when it both deletes or writes files and names a protected path.
 *
 * This is a guard against mistakes, not a sandbox. The user can still run anything with `!` in pi.
 */

import { readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const HOME = resolve(homedir());

const ZONE_LIST: [string, string][] = [
	[join(HOME, "Library"), "your user settings: preferences, keychains, Safari, Teams, Company Portal and Entra sign-in, app data"],
	[join(HOME, "Applications"), "your user apps"],
	["/Library", "system settings: VPN clients, Intune and MDM profiles, Microsoft SSO, launch daemons, system keychains"],
	["/Applications", "installed apps such as Teams, Company Portal, Safari, and the VPN client"],
	["/System", "macOS itself"],
	["/etc", "system configuration: hosts, VPN DNS resolvers, sudoers"],
	["/private/etc", "system configuration: hosts, VPN DNS resolvers, sudoers"],
	["/var/db", "system databases: local users, configuration profiles, privacy (TCC) settings"],
	["/private/var/db", "system databases: local users, configuration profiles, privacy (TCC) settings"],
	["/private/var/root", "the root account"],
	["/opt/cisco", "the Cisco VPN client"],
];

const ALLOW_LIST = [
	"Library/Caches/Homebrew",
	"Library/Caches/pip",
	"Library/Caches/pypoetry",
	"Library/Caches/uv",
	"Library/Caches/ms-playwright",
	"Library/Caches/go-build",
	"Library/Caches/pnpm",
	"Library/Caches/Yarn",
	"Library/Caches/node-gyp",
	"Library/Caches/typescript",
	"Library/Caches/deno",
	"Library/pnpm",
	"Library/Developer/Xcode/DerivedData",
	"Library/Developer/CoreSimulator/Caches",
].map((p) => join(HOME, p));

/** Domains, services, and casks whose settings must not be removed. */
const CRITICAL =
	/(com\.apple\.|microsoft|teams|company[-_ ]?portal|intune|entra|azure|onedrive|outlook|safari|vpn|globalprotect|paloalto|pangp|cisco|anyconnect|secureclient|zscaler|fortinet|forticlient|netskope|openvpn|tunnelblick|wireguard|tailscale|jamf|kandji|mosyle|crowdstrike|falcon|sentinel|defender|wdav|tanium|^system\/)/i;

/** Shell text that may delete or overwrite something; used when a command cannot be followed exactly. */
const SHELL_WRITES =
	/\b(rm|rmdir|unlink|srm|shred|trash|mv|truncate|dd|tee|cp|ditto|rsync|find|defaults|security|profiles|tccutil|launchctl|plutil|plistbuddy|chmod|chown|chflags|sed|perl)\b|>/i;

/** Code that may delete or overwrite files, in any common scripting language. */
const CODE_WRITES =
	/\b(rm|rmdir|unlink|unlinkSync|rmSync|rmdirSync|rmtree|remove|removedirs|removeItem|trashItem|delete|deleteFile|trash|truncate|shred|rename|renameSync|replace|move|moveItem|writeFile|writeFileSync|write_text|write_bytes|copyfile|copytree|copyFile|copyFileSync|cpSync|rm_rf|rm_r|FileUtils|system|exec|execSync|spawn|spawnSync|popen|subprocess|Popen|check_call|check_output|defaults)\b|open\s*\([^)]*,\s*['"][wax+]/;

const REL_MENTION =
	/(^|[\s'"`=(,/])(Library\/(Preferences|Keychains|Safari|Containers|Group Containers|Application Support|LaunchAgents|LaunchDaemons|Cookies|Accounts|Mail|Messages|Managed Preferences|Saved Application State|HTTPStorages|WebKit|Calendars|Mobile Documents|CloudStorage|Security|Cookies)|['"]Library['"])/;

interface Zone {
	path: string;
	what: string;
}

function realOrSelf(p: string): string {
	try {
		return realpathSync.native(p);
	} catch {
		return p;
	}
}

const ZONES: Zone[] = [];
for (const [path, what] of ZONE_LIST) {
	for (const p of new Set([path, realOrSelf(path)])) if (!ZONES.some((z) => z.path === p)) ZONES.push({ path: p, what });
}
const ALLOW = [...new Set(ALLOW_LIST.flatMap((p) => [p, realOrSelf(p)]))];

// APFS is case-insensitive by default, so /library and /Library are the same folder.
const key = (p: string) => p.normalize("NFC").toLowerCase();
function under(child: string, parent: string): boolean {
	const c = key(child);
	const p = key(parent);
	return c === p || c.startsWith(p.endsWith("/") ? p : `${p}/`);
}

/** The real path, resolving symlinks in every existing parent. With follow, also the last part. */
function real(abs: string, follow: boolean): string {
	let cur = follow ? abs : dirname(abs);
	const tail: string[] = follow ? [] : [basename(abs)];
	for (;;) {
		try {
			return join(realpathSync.native(cur), ...tail);
		} catch {
			const parent = dirname(cur);
			if (parent === cur) return abs;
			tail.unshift(basename(cur));
			cur = parent;
		}
	}
}

function insideReason(p: string): string | undefined {
	for (const z of ZONES) {
		if (!under(p, z.path)) continue;
		if (ALLOW.some((a) => under(p, a))) return undefined;
		return `${p}, which is in ${z.path} (${z.what})`;
	}
	return undefined;
}

function containsReason(p: string): string | undefined {
	for (const z of ZONES) if (under(z.path, p) && key(z.path) !== key(p)) return `${p}, which contains ${z.path} (${z.what})`;
	return undefined;
}

function classify(p: string): string | undefined {
	return insideReason(p) ?? containsReason(p);
}

function checkGlob(abs: string, at: number): string | undefined {
	const prefix = abs.slice(0, at);
	const slash = prefix.lastIndexOf("/");
	const dir = resolve(prefix.slice(0, slash + 1) || "/");
	const partial = key(prefix.slice(slash + 1));
	for (const d of new Set([dir, real(dir, true)])) {
		const inside = insideReason(d);
		if (inside) return `${abs}, which matches files in ${d}`;
		const test = (d === "/" ? "/" : `${key(d)}/`) + partial;
		for (const z of ZONES) if (key(z.path).startsWith(test) && key(z.path) !== key(d)) return `${abs}, which can match ${z.path} (${z.what})`;
	}
	return undefined;
}

/** Why changing this absolute path is blocked, or undefined. */
function checkPath(abs: string, follow: boolean): string | undefined {
	const g = abs.search(/[*?[{]/);
	if (g >= 0) return checkGlob(abs, g);
	const lex = resolve(abs);
	return classify(lex) ?? classify(real(lex, follow || /\/\.?$/.test(abs)));
}

function expandHome(text: string): string {
	return text.replace(/\$\{HOME\}|\$HOME\b|(?<![\w~$])~(?=\/|$|[\s'"`)])/g, HOME);
}

/** Why some text (a script, inline code) names a protected path, or undefined. */
function mentionsProtected(text: string): string | undefined {
	const t = expandHome(text);
	for (const m of t.matchAll(/(?:^|[\s'"`=:(\[,{<>|;&])(\/[^\s'"`;|&()<>,\]}\\]*)/g)) {
		const p = m[1].replace(/[.:]+$/, "");
		if (p === "/" || p === "") continue;
		const r = p.search(/[*?[{]/) >= 0 ? checkGlob(p, p.search(/[*?[{]/)) : classify(resolve(p));
		if (r) return r;
	}
	const rel = t.match(REL_MENTION);
	if (rel) return rel[2];
	return undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Shell parsing

type Part = { t: "lit"; s: string } | { t: "tilde"; user: string } | { t: "var"; name: string; def?: string } | { t: "sub" };
type Word = Part[];
interface Cmd {
	words: Word[];
	redirs: { op: string; target: Word }[];
	stdin: string[];
}

function matchParen(src: string, open: number): number {
	let depth = 0;
	for (let i = open; i < src.length; i++) {
		const c = src[i];
		if (c === "\\") {
			i++;
		} else if (c === "'") {
			const j = src.indexOf("'", i + 1);
			i = j < 0 ? src.length : j;
		} else if (c === '"') {
			for (i++; i < src.length && src[i] !== '"'; i++) if (src[i] === "\\") i++;
		} else if (c === "(") {
			depth++;
		} else if (c === ")") {
			depth--;
			if (depth === 0) return i;
		}
	}
	return src.length;
}

function ansiC(s: string): string {
	return s.replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|[0-7]{1,3}|.)/g, (_m, e: string) => {
		if (e[0] === "x" || e[0] === "u") return String.fromCharCode(parseInt(e.slice(1), 16));
		if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
		return ({ n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", f: "\f", v: "\v" } as Record<string, string>)[e] ?? e;
	});
}

/** Command substitutions inside text that the shell expands, such as an unquoted heredoc. */
function substitutionsIn(text: string): string[] {
	const out: string[] = [];
	for (let i = 0; i < text.length; i++) {
		if (text[i] === "\\") i++;
		else if (text[i] === "$" && text[i + 1] === "(") {
			const e = matchParen(text, i + 1);
			out.push(text.slice(i + 2, e));
			i = e;
		} else if (text[i] === "`") {
			const e = text.indexOf("`", i + 1);
			out.push(text.slice(i + 1, e < 0 ? text.length : e));
			i = e < 0 ? text.length : e;
		}
	}
	return out;
}

function parse(src: string): { cmds: Cmd[]; subs: string[] } {
	const cmds: Cmd[] = [];
	const subs: string[] = [];
	const n = src.length;
	let cmd: Cmd = { words: [], redirs: [], stdin: [] };
	let word: Part[] | null = null;
	let lit = "";
	let quoted = false;
	let pendingRedir: string | null = null;
	const heredocs: { delim: string; strip: boolean; expand: boolean; cmd: Cmd }[] = [];
	let i = 0;

	const flush = () => {
		if (lit) (word ??= []).push({ t: "lit", s: lit });
		lit = "";
	};
	const endWord = () => {
		flush();
		if (word) {
			if (pendingRedir === "<<" || pendingRedir === "<<-") {
				const delim = word.map((p) => (p.t === "lit" ? p.s : "")).join("");
				heredocs.push({ delim, strip: pendingRedir === "<<-", expand: !quoted, cmd });
			} else if (pendingRedir) {
				cmd.redirs.push({ op: pendingRedir, target: word });
			} else {
				cmd.words.push(word);
			}
			pendingRedir = null;
		}
		word = null;
		quoted = false;
	};
	const endCmd = () => {
		endWord();
		if (cmd.words.length || cmd.redirs.length || heredocs.some((h) => h.cmd === cmd)) cmds.push(cmd);
		cmd = { words: [], redirs: [], stdin: [] };
	};
	const readHeredocs = (start: number): number => {
		let pos = start;
		for (const h of heredocs.splice(0)) {
			const body: string[] = [];
			while (pos < n) {
				const nl = src.indexOf("\n", pos);
				const end = nl < 0 ? n : nl;
				const line = src.slice(pos, end);
				pos = end + 1;
				if ((h.strip ? line.replace(/^\t+/, "") : line) === h.delim) break;
				body.push(line);
			}
			const text = body.join("\n");
			h.cmd.stdin.push(text);
			if (h.expand) subs.push(...substitutionsIn(text));
		}
		return pos;
	};
	const dollar = (at: number, inDouble: boolean): number => {
		const nx = src[at + 1];
		word ??= [];
		if (nx === "(") {
			const e = matchParen(src, at + 1);
			flush();
			if (src[at + 2] !== "(") subs.push(src.slice(at + 2, e));
			word.push({ t: "sub" });
			return e + 1;
		}
		if (nx === "{") {
			const e = src.indexOf("}", at + 2);
			const inner = src.slice(at + 2, e < 0 ? n : e);
			const m = inner.match(/^([A-Za-z_]\w*|\d+|[@*#?$!-])(?::?[-=](.*))?$/s);
			flush();
			if (m && !inner.startsWith("#") && !inner.startsWith("!")) {
				const def = m[2] === undefined ? undefined : expandHome(m[2]).replace(/^["']|["']$/g, "");
				word.push({ t: "var", name: m[1], def });
			} else {
				word.push({ t: "sub" });
			}
			return (e < 0 ? n : e) + 1;
		}
		if (nx === "'" && !inDouble) {
			let e = at + 2;
			while (e < n && src[e] !== "'") e += src[e] === "\\" ? 2 : 1;
			lit += ansiC(src.slice(at + 2, e));
			quoted = true;
			return e + 1;
		}
		if (nx === '"' && !inDouble) return double(at + 2);
		const name = src.slice(at + 1).match(/^([A-Za-z_]\w*|\d|[@*#?$!-])/);
		if (name) {
			flush();
			word.push({ t: "var", name: name[1] });
			return at + 1 + name[1].length;
		}
		lit += "$";
		return at + 1;
	};
	const backtick = (at: number): number => {
		let e = at + 1;
		while (e < n && src[e] !== "`") e += src[e] === "\\" ? 2 : 1;
		word ??= [];
		flush();
		subs.push(src.slice(at + 1, e).replace(/\\`/g, "`"));
		word.push({ t: "sub" });
		return e + 1;
	};
	const double = (start: number): number => {
		word ??= [];
		quoted = true;
		let j = start;
		while (j < n && src[j] !== '"') {
			const c = src[j];
			if (c === "\\" && /[$`"\\\n]/.test(src[j + 1] ?? "")) {
				if (src[j + 1] !== "\n") lit += src[j + 1];
				j += 2;
			} else if (c === "$") {
				j = dollar(j, true);
			} else if (c === "`") {
				j = backtick(j);
			} else {
				lit += c;
				j++;
			}
		}
		return j + 1;
	};

	while (i < n) {
		const c = src[i];
		const empty = word === null && lit === "";
		if (c === "\\") {
			if (src[i + 1] !== "\n") {
				lit += src[i + 1] ?? "";
				word ??= [];
			}
			i += 2;
		} else if (c === "'") {
			word ??= [];
			quoted = true;
			const j = src.indexOf("'", i + 1);
			const e = j < 0 ? n : j;
			lit += src.slice(i + 1, e);
			i = e + 1;
		} else if (c === '"') {
			i = double(i + 1);
		} else if (c === "$") {
			i = dollar(i, false);
		} else if (c === "`") {
			i = backtick(i);
		} else if (c === " " || c === "\t" || c === "\r") {
			endWord();
			i++;
		} else if (c === "\n") {
			endCmd();
			i = readHeredocs(i + 1);
		} else if (c === "#" && empty) {
			while (i < n && src[i] !== "\n") i++;
		} else if ((c === "<" || c === ">") && src[i + 1] === "(") {
			const e = matchParen(src, i + 1);
			subs.push(src.slice(i + 2, e));
			word ??= [];
			flush();
			word.push({ t: "sub" });
			i = e + 1;
		} else if (c === ">" || c === "<" || (c === "&" && src[i + 1] === ">")) {
			if (word === null && /^\d+$/.test(lit)) lit = "";
			else endWord();
			const op = src.slice(i).match(/^(&>>|&>|<<<|<<-|<<|<>|<&|>&|>>|>\||>|<)/)![1];
			i += op.length;
			if (op === ">&" || op === "<&") {
				const fd = src.slice(i).match(/^\s*(\d+-?|-)(?=[\s;&|)]|$)/);
				if (fd) {
					i += fd[0].length;
					continue;
				}
			}
			pendingRedir = op;
		} else if (c === ";" || c === "|" || c === "&" || c === "(" || c === ")") {
			endCmd();
			i++;
		} else if (c === "~" && (empty || (word === null && /^[A-Za-z_]\w*=$/.test(lit)) || (word === null && /^[A-Za-z_]\w*=.*:$/.test(lit)))) {
			const m = src.slice(i).match(/^~([A-Za-z0-9_.+-]*)(?=[/\s;&|)]|$)/);
			if (m) {
				flush();
				(word ??= []).push({ t: "tilde", user: m[1] });
				i += m[0].length;
			} else {
				lit += c;
				i++;
			}
		} else {
			lit += c;
			i++;
		}
	}
	endCmd();
	readHeredocs(n);
	return { cmds, subs };
}

// ---------------------------------------------------------------------------------------------------------------
// Expansion and checks

interface Cand {
	value: string;
	unknown: boolean;
}
interface State {
	cwd?: string;
	vars: Map<string, Cand[]>;
	raw: string;
	depth: number;
}

function expand(word: Word, st: State): Cand[] {
	let out: Cand[] = [{ value: "", unknown: false }];
	for (const p of word) {
		let opts: Cand[];
		if (p.t === "lit") opts = [{ value: p.s, unknown: false }];
		else if (p.t === "sub") opts = [{ value: "", unknown: true }];
		else if (p.t === "tilde") {
			if (p.user === "") opts = [{ value: HOME, unknown: false }];
			else if (p.user === "+") opts = [{ value: st.cwd ?? "", unknown: !st.cwd }];
			else opts = [{ value: `/Users/${p.user}`, unknown: false }];
		} else if (st.vars.has(p.name)) {
			opts = st.vars.get(p.name)!;
		} else if (p.name === "PWD" && st.cwd) {
			opts = [{ value: st.cwd, unknown: false }];
		} else if (/^[A-Za-z_]\w*$/.test(p.name) && process.env[p.name] !== undefined) {
			opts = [{ value: process.env[p.name]!, unknown: false }];
		} else {
			opts = [{ value: p.def ?? "", unknown: true }];
		}
		const next: Cand[] = [];
		for (const a of out) for (const b of opts) if (next.length < 64) next.push({ value: a.value + b.value, unknown: a.unknown || b.unknown });
		out = next;
	}
	return out;
}

function absOf(value: string, st: State): string | undefined {
	if (isAbsolute(value)) return value;
	if (!st.cwd) return undefined;
	return value === "" ? st.cwd : `${st.cwd}/${value}`;
}

/** Check one target. Unknown parts are treated as empty, and an unknown target is also checked against the whole command text. */
function checkCand(c: Cand, st: State, follow: boolean, verb: string): string | undefined {
	if (c.unknown && c.value === "") return unknownTarget(st, verb);
	const abs = absOf(c.value, st);
	if (abs === undefined) return unknownTarget(st, verb);
	const r = checkPath(abs, follow);
	if (r) return `it would ${verb} ${r}`;
	if (c.unknown) return unknownTarget(st, verb);
	return undefined;
}

function unknownTarget(st: State, verb: string): string | undefined {
	const m = mentionsProtected(st.raw);
	return m ? `it would ${verb} a path that is only known when it runs, and the command names ${m}` : undefined;
}

function checkAll(cands: Cand[], st: State, verb: string, follow = false): string | undefined {
	for (const c of cands) {
		const r = checkCand(c, st, follow, verb);
		if (r) return r;
	}
	return undefined;
}

function readScript(c: Cand, st: State): string | undefined {
	if (c.unknown) return undefined;
	const abs = absOf(c.value, st);
	if (!abs) return undefined;
	try {
		if (!statSync(abs).isFile()) return undefined;
		return readFileSync(abs, "utf8").slice(0, 512 * 1024);
	} catch {
		return undefined;
	}
}

const isOpt = (c: Cand | undefined) => !!c && !c.unknown && c.value.length > 1 && c.value.startsWith("-");

/** Split arguments into positional ones and option values. valueOpts are options that take the next argument. */
function split(args: Cand[], valueOpts: string[] = []): { pos: Cand[]; flags: string[]; vals: Map<string, Cand[]> } {
	const pos: Cand[] = [];
	const flags: string[] = [];
	const vals = new Map<string, Cand[]>();
	let i = 0;
	for (; i < args.length; i++) {
		const a = args[i];
		if (!a.unknown && a.value === "--") {
			i++;
			break;
		}
		if (!isOpt(a)) {
			pos.push(a);
			continue;
		}
		const eq = a.value.indexOf("=");
		const name = eq > 0 && a.value.startsWith("--") ? a.value.slice(0, eq) : a.value;
		flags.push(name);
		if (eq > 0 && a.value.startsWith("--")) {
			vals.set(name, [...(vals.get(name) ?? []), { value: a.value.slice(eq + 1), unknown: false }]);
		} else if (valueOpts.includes(name) && i + 1 < args.length) {
			vals.set(name, [...(vals.get(name) ?? []), args[++i]]);
		}
	}
	pos.push(...args.slice(i));
	return { pos, flags, vals };
}

const KEYWORDS = new Set(["if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{", "}", "time", "esac", "function", "coproc"]);
const DECLARE = new Set(["export", "local", "declare", "typeset", "readonly"]);
const SHELLS = /^(sh|bash|zsh|dash|ksh|mksh|yash)$/;
const INTERPRETERS = /^(python[\d.]*|pythonw|pypy3?|node|nodejs|perl[\d.]*|ruby|php|swift|deno|bun|lua|tclsh|rscript|pwsh|jxa|irb|uv|uvx)$/;
const DIRECT_DELETE = new Set(["rm", "grm", "rmdir", "unlink", "srm", "shred", "gshred", "trash", "trash-put", "rmtrash", "truncate"]);
const COPY_INTO = new Set(["cp", "gcp", "ditto", "install", "ginstall", "ln", "gln", "rsync", "scp", "cpio"]);
const DISK_VERBS = /^(erasedisk|erasevolume|reformat|zerodisk|randomdisk|secureerase|partitiondisk|splitpartition|mergepartitions|resizevolume|deletevolume|deletecontainer|deletesnapshot|deletevolumegroup|deletepv|deletelvg|deletelv|deleteraid|removefromraid|convert|decryptvolume|deleteFileVault)$/i;

/** Program names that the guard knows can change settings. Used for find -exec and xargs. */
function guarded(name: string): boolean {
	return (
		DIRECT_DELETE.has(name) ||
		COPY_INTO.has(name) ||
		SHELLS.test(name) ||
		INTERPRETERS.test(name) ||
		/^(mv|gmv|dd|tee|chmod|chown|chgrp|chflags|sed|gsed|plutil|plistbuddy|defaults|security|profiles|tccutil|networksetup|launchctl|systemextensionsctl|dscl|sysadminctl|dseditgroup|diskutil|tmutil|nvram|csrutil|spctl|fdesetup|pkgutil|brew|jamf|osascript|tar|gtar|bsdtar|unzip|eval|xargs)$/.test(name)
	);
}

function analyze(src: string, st: State): string | undefined {
	if (st.depth > 6) return undefined;
	const { cmds, subs } = parse(src);
	for (const s of subs) {
		const r = analyze(s, { ...st, vars: new Map(st.vars), depth: st.depth + 1 });
		if (r) return r;
	}
	for (const c of cmds) {
		const r = runCmd(c, st);
		if (r) return r;
	}
	return undefined;
}

function runCmd(c: Cmd, st: State): string | undefined {
	const stdin = [...c.stdin];
	for (const r of c.redirs) {
		const targets = expand(r.target, st);
		if (/^(>|>>|>\||&>|&>>|<>)$/.test(r.op)) {
			const bad = checkAll(targets, st, "write to", true);
			if (bad) return bad;
		} else if (r.op === "<<<") {
			stdin.push(...targets.map((t) => t.value));
		} else if (r.op === "<") {
			for (const t of targets) {
				const text = readScript(t, st);
				if (text !== undefined) stdin.push(text);
			}
		}
	}

	let args: Cand[] = c.words.flatMap((w) => expand(w, st));
	while (args.length && !args[0].unknown && KEYWORDS.has(args[0].value)) args.shift();
	if (!args.length) return undefined;

	if (!args[0].unknown && (args[0].value === "for" || args[0].value === "select") && args.length >= 2) {
		const inAt = args.findIndex((a, i) => i >= 2 && a.value === "in");
		st.vars.set(args[1].value, inAt > 0 ? args.slice(inAt + 1) : [{ value: "", unknown: true }]);
		return undefined;
	}

	const assign = (a: Cand) => {
		const m = a.value.match(/^([A-Za-z_]\w*)\+?=(.*)$/s);
		if (m) st.vars.set(m[1], [{ value: m[2], unknown: a.unknown }]);
	};
	let k = 0;
	while (k < args.length && /^[A-Za-z_]\w*\+?=/.test(args[k].value)) k++;
	if (k === args.length) {
		args.forEach(assign);
		return undefined;
	}
	const envPrefix = args.slice(0, k);
	args = args.slice(k);
	if (!args[0].unknown && DECLARE.has(args[0].value)) {
		args.slice(1).forEach(assign);
		return undefined;
	}
	if (!args[0].unknown && args[0].value === "unset") {
		for (const a of args.slice(1)) st.vars.delete(a.value);
		return undefined;
	}
	if (!args[0].unknown && (args[0].value === "cd" || args[0].value === "pushd")) {
		const t = args.slice(1).find((a) => !isOpt(a));
		if (!t) st.cwd = HOME;
		else if (t.unknown || t.value === "-") st.cwd = undefined;
		else st.cwd = isAbsolute(t.value) ? resolve(t.value) : st.cwd ? resolve(st.cwd, t.value) : undefined;
		return undefined;
	}
	if (envPrefix.some((a) => a.unknown)) {
		/* the command still runs; its arguments are checked below */
	}
	return dispatch(args, stdin, st, false);
}

function nameOf(c: Cand): string {
	return basename(c.value).toLowerCase();
}

function dispatch(argsIn: Cand[], stdin: string[], st: State, stdinArgs: boolean): string | undefined {
	let args = argsIn;
	// Strip wrappers that run another command.
	for (let guard = 0; guard < 16 && args.length; guard++) {
		const n = nameOf(args[0]);
		if (args[0].unknown) break;
		let skip = -1;
		if (n === "sudo" || n === "doas") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) {
				if (args[i].value === "--") {
					i++;
					break;
				}
				if (/^-[ugChprtUTD]$/.test(args[i].value)) i++;
				i++;
			}
			skip = i;
		} else if (n === "env") {
			let i = 1;
			for (; i < args.length; i++) {
				const v = args[i].value;
				if (v === "-S" || v === "--split-string") return analyze(args.slice(i + 1).map((a) => a.value).join(" "), { ...st, depth: st.depth + 1 });
				if (v === "-u" || v === "--unset" || v === "-P") i++;
				else if (v === "-C" || v === "--chdir") {
					const d = args[++i];
					st = { ...st, cwd: d && !d.unknown ? (isAbsolute(d.value) ? d.value : st.cwd && resolve(st.cwd, d.value)) : undefined };
				} else if (!isOpt(args[i]) && !/^[A-Za-z_]\w*=/.test(v)) break;
			}
			skip = i;
		} else if (n === "nice" || n === "renice") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += args[i].value === "-n" ? 2 : 1;
			skip = i;
		} else if (n === "nohup" || n === "command" || n === "builtin" || n === "exec" || n === "time" || n === "chronic" || n === "unbuffer" || n === "stdbuf" || n === "gstdbuf") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += args[i].value === "-a" ? 2 : 1;
			skip = i;
		} else if (n === "timeout" || n === "gtimeout") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += /^-[sk]$/.test(args[i].value) ? 2 : 1;
			skip = i + 1;
		} else if (n === "caffeinate") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += /^-[tw]$/.test(args[i].value) ? 2 : 1;
			skip = i;
		} else if (n === "arch") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += /^-(arch|e|d)$/.test(args[i].value) ? 2 : 1;
			skip = i;
		} else if (n === "xargs" || n === "parallel") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += /^-[ILnPsEJdRS]$/.test(args[i].value) || args[i].value === "--max-args" ? 2 : 1;
			skip = i;
			stdinArgs = true;
		} else if (n === "watch") {
			let i = 1;
			while (i < args.length && isOpt(args[i])) i += /^-[nd]$/.test(args[i].value) ? 2 : 1;
			skip = i;
		}
		if (skip < 0) break;
		args = args.slice(skip);
	}
	if (!args.length) return undefined;

	const head = args[0];
	const rest = args.slice(1);
	if (head.unknown) {
		// The program name comes from a variable or $(...), so treat it as one that can delete.
		return checkAll(rest.filter((a) => !isOpt(a)), st, "pass to a program known only when it runs");
	}
	const name = nameOf(head);

	if (stdinArgs && guarded(name)) {
		const m = mentionsProtected(st.raw);
		if (m) return `${name} gets its files from stdin (xargs), and the command names ${m}`;
	}

	const block = (what: string) => `${what}`;

	// Vendor uninstallers, for example the VPN or Microsoft uninstall scripts.
	if (/uninstall|removal[-_]?tool|zap/i.test(name)) {
		const abs = absOf(head.value, st);
		if (!head.value.includes("/") || (abs && (insideReason(resolve(abs)) || /^\/(opt|usr\/local)\//.test(abs)))) {
			if (head.value.includes("/")) return block(`it runs the uninstaller ${head.value}`);
		}
	}

	if (DIRECT_DELETE.has(name)) {
		const { pos } = split(rest, ["-s", "-r", "--size", "--reference", "-n", "-u"]);
		return checkAll(pos, st, name === "truncate" ? "truncate" : "delete");
	}
	if (name === "gio") {
		if (rest[0]?.value === "trash" || rest[0]?.value === "remove") return checkAll(split(rest.slice(1)).pos, st, "delete");
		return undefined;
	}
	if (name === "mv" || name === "gmv") {
		const { pos, vals } = split(rest, ["-t", "--target-directory", "-S", "--suffix"]);
		const dest = vals.get("-t") ?? vals.get("--target-directory") ?? [];
		const sources = dest.length ? pos : pos.slice(0, -1);
		const target = dest.length ? dest : pos.slice(-1);
		return checkAll(sources, st, "move away") ?? checkAll(target, st, "move files into", true);
	}
	if (COPY_INTO.has(name)) {
		const { pos, vals, flags } = split(rest, ["-t", "--target-directory", "-S", "-m", "-o", "-g", "-e", "--rsh", "--exclude", "--include", "--filter", "-f", "--files-from", "--rsync-path", "-i", "-F", "-P", "-c", "-o", "-l", "-B", "--bwlimit", "--chmod", "--chown"]);
		const remote = (c: Cand) => /^[^/]*:/.test(c.value) && !c.value.startsWith("/");
		const dest = (vals.get("-t") ?? vals.get("--target-directory") ?? (pos.length >= 2 ? pos.slice(-1) : [])).filter((c) => !remote(c));
		const bad = checkAll(dest, st, "write into", true);
		if (bad) return bad;
		if (name === "rsync" && flags.includes("--remove-source-files")) return checkAll(pos.slice(0, -1).filter((c) => !remote(c)), st, "delete");
		return undefined;
	}
	if (name === "dd") {
		return checkAll(
			rest.filter((a) => a.value.startsWith("of=")).map((a) => ({ value: a.value.slice(3), unknown: a.unknown })),
			st,
			"overwrite",
			true,
		);
	}
	if (name === "tee" || name === "gtee") return checkAll(split(rest).pos, st, "write to", true);
	if (/^(chmod|chown|chgrp|chflags|gchmod|gchown|gchgrp)$/.test(name)) {
		const { pos, flags } = split(rest, ["--reference"]);
		return checkAll(flags.includes("--reference") ? pos : pos.slice(1), st, "change permissions on", true);
	}
	if (name === "sed" || name === "gsed") {
		const { pos, flags, vals } = split(rest, ["-e", "-f", "--expression", "--file", "-l"]);
		if (!flags.some((f) => /^-i|^--in-place|^-[a-zA-Z]*i/.test(f))) return undefined;
		const files = vals.has("-e") || vals.has("-f") || vals.has("--expression") || vals.has("--file") ? pos : pos.slice(1);
		return checkAll(files, st, "edit in place", true);
	}
	if (/^perl[\d.]*$/.test(name) && rest.some((a) => /^-[a-zA-Z]*i/.test(a.value))) {
		const { pos, vals } = split(rest, ["-e", "-E", "-M", "-I"]);
		const files = vals.has("-e") || vals.has("-E") ? pos : pos.slice(1);
		const bad = checkAll(files, st, "edit in place", true);
		if (bad) return bad;
	}
	if (name === "plutil") {
		const { pos, flags } = split(rest, ["-o", "-s", "-e"]);
		if (flags.some((f) => /^-(remove|replace|insert|convert|create|lint)$/.test(f) && f !== "-lint")) return checkAll(pos, st, "change the plist", true);
		return undefined;
	}
	if (name === "plistbuddy") {
		const { pos, vals } = split(rest, ["-c"]);
		if ((vals.get("-c") ?? []).some((c) => c.unknown || /^\s*(delete|set|add|clear|merge|import|copy|save)\b/i.test(c.value))) return checkAll(pos, st, "change the plist", true);
		return undefined;
	}
	if (name === "defaults") {
		const { pos } = split(rest.filter((a, i) => !(a.value === "-host" || rest[i - 1]?.value === "-host") && a.value !== "-currentHost"));
		const sub = pos[0]?.value.toLowerCase() ?? "";
		const domain = pos[1]?.value ?? "";
		if (/^(delete|remove|import|rename)$/.test(sub)) return block(`defaults ${sub} ${domain} deletes or replaces settings`);
		if (sub === "write" || sub === "-write") {
			if (CRITICAL.test(domain) || /^(-g|-globaldomain|nsglobaldomain)$/i.test(domain)) return block(`defaults write ${domain} changes protected system or app settings`);
			if (domain.startsWith("/") || domain.startsWith("~")) return checkAll([pos[1]], st, "write settings to", true);
		}
		return undefined;
	}
	if (name === "security") {
		const sub = rest.find((a) => !isOpt(a))?.value ?? "";
		const words = rest.map((a) => a.value);
		if (/^(delete|remove)-/.test(sub)) return block(`security ${sub} removes keychain items`);
		if (sub === "authorizationdb" && words.some((w) => /^(write|remove|merge|smartcard)$/.test(w))) return block("security authorizationdb changes system authorization rules");
		if (sub === "trust-settings-import" || sub === "set-keychain-password") return block(`security ${sub} replaces keychain settings`);
		if ((sub === "default-keychain" || sub === "login-keychain" || sub === "list-keychains") && words.includes("-s")) return block(`security ${sub} -s changes which keychains are used`);
		return undefined;
	}
	if (name === "profiles") {
		if (rest.some((a) => /^(remove|-R|-D|-r|-removeall|renew)$/.test(a.value))) return block("profiles removes or replaces configuration profiles (Intune, VPN, Entra SSO)");
		return undefined;
	}
	if (name === "tccutil") {
		if (rest.some((a) => a.value.toLowerCase() === "reset")) return block("tccutil reset clears privacy permissions");
		return undefined;
	}
	if (name === "networksetup") {
		const bad = rest.find((a) => /^-(remove|delete|create|setv[46]off|setnetworkserviceenabled|setdnsservers|setsearchdomains|setwebproxy|setsecurewebproxy|setautoproxyurl|setproxybypassdomains|ordernetworkservices|switchtolocation)/i.test(a.value));
		if (bad) return block(`networksetup ${bad.value} changes network or VPN settings`);
		return undefined;
	}
	if (name === "scutil") {
		if (rest.some((a) => a.value === "--set")) return block("scutil --set changes system names");
		if (stdin.some((t) => /^\s*(remove|set|notify)\b/im.test(t))) return block("scutil changes the system configuration store");
		return undefined;
	}
	if (name === "launchctl") {
		const sub = rest.find((a) => !isOpt(a))?.value.toLowerCase() ?? "";
		if (/^(bootout|remove|unload|disable|kill|kickstart)$/.test(sub)) {
			const text = rest.map((a) => a.value).join(" ");
			if (CRITICAL.test(text) || /\bsystem\b|^\/Library|\s\/Library|\/System\//.test(text)) return block(`launchctl ${sub} stops a system, Microsoft, VPN, or security service`);
		}
		return undefined;
	}
	if (name === "systemextensionsctl") {
		if (rest.some((a) => /^(uninstall|reset)$/.test(a.value))) return block("systemextensionsctl removes system extensions, such as the VPN or security agent");
		return undefined;
	}
	if (/^(kextunload|kmutil)$/.test(name)) {
		if (name === "kextunload" || rest.some((a) => /^(unload|clear-staging)$/.test(a.value))) return block(`${name} unloads kernel extensions`);
		return undefined;
	}
	if (name === "dscl") {
		if (rest.some((a) => /^-(delete|remove|merge|change|passwd|create|append)$/i.test(a.value))) return block("dscl changes local users or groups");
		return undefined;
	}
	if (name === "sysadminctl") {
		const bad = rest.find((a) => /^-(deleteUser|resetPasswordFor|secureTokenOff|guestAccount|addUser|adminUser|filesystem)$/i.test(a.value));
		if (bad) return block(`sysadminctl ${bad.value} changes user accounts`);
		return undefined;
	}
	if (name === "dseditgroup") {
		if (rest.some((a) => a.value === "delete" || a.value === "-d" || a.value === "edit")) return block("dseditgroup changes group membership");
		return undefined;
	}
	if (name === "diskutil") {
		const pos = split(rest).pos.map((a) => a.value);
		const verb = /^(apfs|ap|cs|coreStorage|appleRAID|ar)$/i.test(pos[0] ?? "") ? pos[1] : pos[0];
		if (verb && (DISK_VERBS.test(verb) || /^erase/i.test(verb))) return block(`diskutil ${pos.slice(0, 2).join(" ")} erases or changes disks`);
		return undefined;
	}
	if (name === "tmutil") {
		const sub = rest[0]?.value.toLowerCase() ?? "";
		if (/^(delete|deletelocalsnapshots|thinlocalsnapshots|deleteinprogress|disable|removedestination|setdestination|disablelocal)$/.test(sub)) return block(`tmutil ${sub} deletes backups or turns them off`);
		return undefined;
	}
	if (name === "nvram") {
		if (rest.some((a) => a.value === "-c" || a.value === "-d" || /=/.test(a.value) || a.value === "-f")) return block("nvram changes firmware settings");
		return undefined;
	}
	if (name === "csrutil" || name === "spctl" || name === "fdesetup" || name === "bputil" || name === "pmset" || name === "systemsetup" || name === "softwareupdate") {
		const words = rest.map((a) => a.value.toLowerCase());
		if (name === "csrutil" && words.some((w) => /^(disable|clear|enable)$/.test(w))) return block("csrutil changes System Integrity Protection");
		if (name === "spctl" && words.some((w) => /^--(master-disable|global-disable|disable|remove|add|reset-default|enable)$/.test(w))) return block("spctl changes Gatekeeper settings");
		if (name === "fdesetup" && words.some((w) => /^(disable|remove|removerecovery|changerecovery|enable|add)$/.test(w))) return block("fdesetup changes FileVault");
		if (name === "bputil") return block("bputil changes the boot security policy");
		if (name === "pmset" && words.some((w) => !w.startsWith("-g") && w !== "-g")) return block("pmset changes power settings");
		if (name === "systemsetup" && words.some((w) => w.startsWith("-set"))) return block("systemsetup changes system settings");
		if (name === "softwareupdate" && words.some((w) => /^--(reset-ignored|ignore|schedule|clear-catalog|set-catalog)$/.test(w))) return block("softwareupdate changes update settings");
		return undefined;
	}
	if (name === "pkgutil") {
		if (rest.some((a) => a.value === "--forget" || a.value === "--unlink")) return block("pkgutil removes installed package records");
		return undefined;
	}
	if (name === "brew") {
		const pos = split(rest).pos.map((a) => a.value);
		const sub = pos[0] ?? "";
		if (/^(uninstall|remove|rm|zap|reinstall)$/.test(sub)) {
			if (sub === "zap" || rest.some((a) => a.value === "--zap")) return block("brew --zap deletes the app's settings in ~/Library");
			const crit = pos.slice(1).find((p) => CRITICAL.test(p));
			if (crit) return block(`brew ${sub} ${crit} removes a Microsoft, VPN, or security app`);
		}
		return undefined;
	}
	if (name === "jamf") {
		if (rest.some((a) => /^remove/i.test(a.value))) return block("jamf removes device management");
		return undefined;
	}
	if (name === "mdmclient" || name === "app-sso") {
		if (rest.some((a) => /remove|delete|reset|unregister|deregister|-d\b/i.test(a.value))) return block(`${name} changes device management or Entra single sign-on`);
		return undefined;
	}
	if (name === "find" || name === "gfind") {
		let i = 0;
		const roots: Cand[] = [];
		while (i < rest.length && /^-[HLPEXdsx]$|^-O\d$/.test(rest[i].value)) i++;
		for (; i < rest.length; i++) {
			const v = rest[i].value;
			if (v === "-f") roots.push(rest[++i]);
			else if (!rest[i].unknown && (/^[-(!]/.test(v) || v === ")")) break;
			else roots.push(rest[i]);
		}
		const expr = rest.slice(i);
		let destructive = expr.some((a) => a.value === "-delete");
		expr.forEach((a, j) => {
			if (/^-(exec|execdir|ok|okdir)$/.test(a.value)) {
				const prog = expr[j + 1];
				if (!prog || prog.unknown || guarded(nameOf(prog))) destructive = true;
			}
		});
		if (!destructive) return undefined;
		return checkAll(roots.length ? roots : [{ value: ".", unknown: false }], st, "delete or change files under", true);
	}
	if (name === "fd" || name === "fdfind") {
		if (!rest.some((a) => /^(-x|-X|--exec|--exec-batch)$/.test(a.value))) return undefined;
		const pos = split(rest, ["-e", "-E", "-t", "-d", "--max-depth", "--extension", "--exclude", "--type"]).pos;
		return checkAll(pos.length >= 2 ? pos.slice(1, 2) : [{ value: ".", unknown: false }], st, "run a command on files under", true);
	}
	if (/^(g|bsd)?tar$/.test(name)) {
		const first = rest[0]?.value ?? "";
		const extract = rest.some((a) => a.value === "--extract" || a.value === "-x" || a.value === "--get") || /^-?[a-zA-Z]*x/.test(first);
		if (!extract) return undefined;
		const { vals } = split(rest, ["-C", "--directory", "-f", "--file"]);
		const dir = vals.get("-C") ?? vals.get("--directory") ?? [{ value: ".", unknown: false }];
		return checkAll(dir, st, "extract files into", true);
	}
	if (name === "unzip") {
		const { vals } = split(rest, ["-d", "-x", "-P"]);
		return checkAll(vals.get("-d") ?? [{ value: ".", unknown: false }], st, "extract files into", true);
	}
	if (name === "osascript") {
		const { pos, vals } = split(rest, ["-e", "-l", "-s"]);
		const code = [...(vals.get("-e") ?? []).map((c) => c.value), ...(pos[0] ? [readScript(pos[0], st) ?? ""] : []), ...stdin].join("\n");
		for (const m of code.matchAll(/do shell script\s+"((?:[^"\\]|\\.)*)"/gi)) {
			const r = analyze(m[1].replace(/\\(.)/g, "$1"), { ...st, vars: new Map(st.vars), depth: st.depth + 1 });
			if (r) return r;
		}
		if (/\b(delete|remove|empty\s+(the\s+)?trash|move\b[^\n]*\bto\s+(the\s+)?trash|set\s+the\s+value)\b/i.test(code)) {
			const m = mentionsProtected(code) ?? (/System Events|System Settings|System Preferences|login item|keychain/i.test(code) ? "System Events or System Settings" : undefined);
			if (m) return block(`osascript deletes or changes things, and the script names ${m}`);
		}
		if (!code.trim()) return codeFromPipe(st, "osascript");
		return undefined;
	}
	if (name === "eval") return analyze(rest.map((a) => a.value).join(" "), { ...st, depth: st.depth + 1 });
	if (name === "source" || name === ".") {
		const text = rest[0] && readScript(rest[0], st);
		return text === undefined ? undefined : analyze(text, { ...st, raw: text, depth: st.depth + 1 });
	}
	if (SHELLS.test(name)) {
		let i = 0;
		let inline: string | undefined;
		for (; i < rest.length && isOpt(rest[i]); i++) {
			const v = rest[i].value;
			if (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(v)) {
				inline = rest[i + 1]?.value ?? "";
				break;
			}
			if (v === "-o" || v === "+o" || v === "--rcfile" || v === "--init-file") i++;
		}
		if (inline !== undefined) return analyze(inline, { ...st, vars: new Map(st.vars), raw: `${st.raw}\n${inline}`, depth: st.depth + 1 });
		const file = rest[i];
		if (file && !rest.some((a) => a.value === "-s")) {
			const abs = absOf(file.value, st);
			if (abs && /uninstall/i.test(basename(abs)) && (insideReason(resolve(abs)) || /^\/(opt|usr\/local)\//.test(abs))) return block(`it runs the uninstaller ${abs}`);
			const text = readScript(file, st);
			if (text !== undefined) return analyze(text, { cwd: st.cwd, vars: new Map(), raw: text, depth: st.depth + 1 });
			return undefined;
		}
		if (stdin.length) {
			for (const t of stdin) {
				const r = analyze(t, { ...st, vars: new Map(st.vars), raw: `${st.raw}\n${t}`, depth: st.depth + 1 });
				if (r) return r;
			}
			return undefined;
		}
		return codeFromPipe(st, name);
	}
	if (INTERPRETERS.test(name)) {
		// Python's -I is a flag (isolated mode); for Ruby and Perl it takes an include directory.
		const python = /^(python[\d.]*|pythonw|pypy3?)$/.test(name);
		const valueOpts = ["-c", "-e", "-E", "--eval", "-p", "--print", "-m", "-M", "-r", "--require", "-W", "-X"];
		if (!python) valueOpts.push("-I");
		const { pos, vals } = split(rest, valueOpts);
		const inline = [...(vals.get("-c") ?? []), ...(vals.get("-e") ?? []), ...(vals.get("-E") ?? []), ...(vals.get("--eval") ?? []), ...(vals.get("-p") ?? []), ...(vals.get("--print") ?? [])].map((c) => c.value);
		let files = pos;
		if ((name === "deno" || name === "bun" || name === "uv") && /^(run|eval|x)$/.test(files[0]?.value ?? "")) {
			if (files[0].value === "eval") inline.push(files[1]?.value ?? "");
			files = files.slice(1);
		}
		const fileText = inline.length || !files[0] ? undefined : readScript(files[0], st);
		const code = [...inline, fileText ?? "", ...stdin].join("\n");
		if (!code.trim()) return vals.has("-m") || files.length ? undefined : codeFromPipe(st, name);
		if (CODE_WRITES.test(code)) {
			const m = mentionsProtected(code);
			if (m) return block(`${name} code that deletes or writes files names ${m}`);
		}
		return undefined;
	}
	return undefined;
}

/** A shell or interpreter that reads its program from a pipe. The program is somewhere in the command text. */
function codeFromPipe(st: State, name: string): string | undefined {
	if (!SHELL_WRITES.test(st.raw) && !CODE_WRITES.test(st.raw)) return undefined;
	const m = mentionsProtected(st.raw);
	return m ? `${name} runs a program from a pipe, and the command names ${m}` : undefined;
}

/** Why a bash command is blocked, or undefined. Exported for tests. */
export function checkCommand(command: string, cwd: string): string | undefined {
	try {
		return analyze(command, { cwd: resolve(cwd), vars: new Map(), raw: command, depth: 0 });
	} catch (err) {
		// The guard must fail closed when it cannot follow a command that may touch protected settings.
		const m = mentionsProtected(command);
		if (m && SHELL_WRITES.test(command)) return `mac-guard could not parse the command (${err instanceof Error ? err.message : String(err)}), and it names ${m}`;
		return undefined;
	}
}

/** Why writing this file with the write or edit tool is blocked, or undefined. Exported for tests. */
export function checkFilePath(path: string, cwd: string): string | undefined {
	let p = path.replace(/[\u00A0\u2000-\u200B\u202F\u205F\u3000]/g, " ");
	if (p.startsWith("@")) p = p.slice(1);
	if (p === "~") p = HOME;
	else if (p.startsWith("~/")) p = join(HOME, p.slice(2));
	const abs = isAbsolute(p) ? resolve(p) : resolve(cwd, p);
	const r = classify(abs) ?? classify(real(abs, true));
	return r ? `it would write to ${r}` : undefined;
}

function reason(detail: string): string {
	return `mac-guard blocked this: ${detail}. Deleting or changing files there can break macOS settings, the VPN, Teams, Entra sign-in, Safari, or the keychain, and the user may have to set up the Mac again. Do not try another way to do it. Tell the user the exact command or change you wanted to make and why, and let them do it themselves.`;
}

export default function (pi: ExtensionAPI) {
	// Every protected path is a macOS one; elsewhere the guard only produces false positives.
	if (process.platform !== "darwin") return;
	pi.on("tool_call", async (event, ctx) => {
		const input = (event.input ?? {}) as Record<string, unknown>;
		const cwd = (ctx as { cwd?: string } | undefined)?.cwd ?? process.cwd();
		let detail: string | undefined;
		if (event.toolName === "bash") {
			detail = checkCommand(String(input.command ?? ""), typeof input.cwd === "string" ? resolve(cwd, input.cwd) : cwd);
		} else if (event.toolName === "write" || event.toolName === "edit") {
			const path = input.path ?? input.file_path;
			if (typeof path === "string") detail = checkFilePath(path, cwd);
		}
		if (detail) return { block: true, reason: reason(detail) };
		return undefined;
	});
}
