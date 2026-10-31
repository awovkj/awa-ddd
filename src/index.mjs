/** Native DeepSeek Harness Cordis plugin: named exports preserve injection. */
import { defineTool } from '@deepseek-ai/dsh-tools';
import z from '@deepseek-ai/schemastery';
import { DEFAULT_WORKSPACE, safeErrorText } from './bridge.mjs';
import { toolDefinitions } from './tools.mjs';
import { apply as applyMode, name as modeName } from './mode.mjs';

export const name = 'awa-ddd';

/**
 * 只声明真正必需的依赖。
 *
 * 渗透模式（systemPrompt / sessionProjections / commands）刻意**不**写在这里：
 * 顶层 inject 是必需语义，宿主缺任一服务会导致整个插件——包括 10 组评估工具——
 * 都不加载。模式是可选能力，由 applyMode 自行探测并在缺服务时降级。
 */
export const inject = ['tools'];

export const Config = z.object({
  workspace: z.string().default(DEFAULT_WORKSPACE).description('Absolute assessment-state directory outside the plugin package. It is not changed by model tool arguments.'),
  pythonExecutable: z.string().default(process.platform === 'win32' ? 'python' : 'python3').description('Python 3.10+ executable path or executable name. No shell command or extra flags.'),
  executionBackend: z.union(['native', 'wsl']).default('native').description('Run locally or in an explicitly selected WSL distribution. WSL does not change scope or translate localhost targets.'),
  wslDistribution: z.string().default('kali-linux').description('WSL distribution name. Use a separate assessment workspace for each execution environment.'),
  wslPythonExecutable: z.string().default('python3').description('Linux Python executable name or path for WSL, without shell arguments.'),
  timeoutMs: z.number().min(1000).max(600000).default(120000).description('Per-call engine timeout in milliseconds; cancellation is enforced by the bridge.'),
});

export function apply(ctx, config = {}) {
  const lifecycle = new AbortController();
  ctx.effect(() => () => lifecycle.abort(new Error('awa-ddd plugin disposed')));

  // 评估工具是核心能力，任何情况下都要先注册成功。
  for (const definition of toolDefinitions(defineTool, config, undefined, lifecycle.signal)) {
    ctx.tools.register(definition);
  }

  // 渗透模式是可选的界面/提示能力：缺宿主服务或注册失败只记录，不影响工具。
  try {
    applyMode(ctx);
  } catch (error) {
    console.error(`[${name}] penetration mode unavailable (assessment tools unaffected): ${safeErrorText(error?.message ?? error, 300)}`);
  }
}

export { modeName };
