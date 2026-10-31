/** Optional DOM control; the server projection, never local storage, owns truth. */
window.__ModuleLoader__.load({
  id: 'awa-ddd/client',
  factory: () => {
    const STYLE_ID = 'awa-ddd-penetration-style';
    const BUTTON_ID = 'awa-ddd-fallback-btn';
    const COPY = {
      zh: { 'mode.off': '渗透模式', 'mode.on': '渗透模式已启用' },
      en: { 'mode.off': 'Penetration', 'mode.on': 'Penetration on' },
    };

    const mark = (key, value) => {
      try { if (typeof document !== 'undefined') document.documentElement.dataset[key] = value; }
      catch { /* Optional diagnostics never affect the host. */ }
    };

    function installButton(ctx) {
      if (typeof document === 'undefined' || document.getElementById(BUTTON_ID)) return () => {};
      const states = new Map();
      const pendingReads = new Map();
      let button;
      let style;
      let observer;
      let currentSession;
      let busy = false;
      let disposed = false;
      let lastError = '';
      let errorTimer;

      const readSession = () => {
        const fromDom = document.querySelector('[data-conversation-session]')?.getAttribute('data-conversation-session');
        const page = window.location ?? (typeof location === 'undefined' ? undefined : location);
        const fromUrl = /\/session\/([\w-]+)/.exec(page?.pathname ?? '')?.[1]
          ?? new URLSearchParams(page?.search ?? '').get('session');
        const value = fromDom || fromUrl;
        return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,199}$/.test(value) ? value : undefined;
      };

      const paint = () => {
        if (disposed || !button) return;
        const active = states.get(currentSession);
        button.dataset.active = active === undefined ? 'unknown' : String(active);
        button.dataset.error = String(Boolean(lastError));
        button.disabled = busy;
        button.setAttribute('aria-busy', String(busy));
        button.setAttribute('aria-pressed', active === undefined ? 'mixed' : String(active));
        button.textContent = lastError ? `切换失败：${lastError}` : active ? '渗透模式 · 已启用' : '渗透模式';
        button.title = lastError || (currentSession
          ? '仅影响本次会话的系统提示与工作方式；点击前核对服务端状态'
          : '请先打开一个会话');
      };

      const fail = (error, sessionId = currentSession) => {
        if (disposed || sessionId !== currentSession) return;
        lastError = String(error?.message ?? error).slice(0, 240);
        clearTimeout(errorTimer);
        paint();
        errorTimer = setTimeout(() => { lastError = ''; paint(); }, 4000);
      };

      const execute = async (sessionId, line) => {
        const commands = ctx?.remote?.commands;
        if (typeof commands?.execute !== 'function') throw new Error('宿主接口未就绪');
        const result = await commands.execute(sessionId, line, []);
        if (result?.ok !== true) throw new Error(result?.error?.message ?? '宿主未确认命令成功');
        // DSH's command RPC returns { commandId, result: { kind, text } }.
        // Keep accepting the older flat { kind, text } projection for compatibility.
        const value = result.value?.result ?? result.value;
        if (value?.kind !== 'success') throw new Error(value?.text ?? '命令未成功执行');
        return value;
      };

      const readState = sessionId => {
        if (pendingReads.has(sessionId)) return pendingReads.get(sessionId);
        const promise = (async () => {
          const reply = await execute(sessionId, '/penetration status');
          const text = reply.text?.trim();
          if (text !== 'Penetration mode on.' && text !== 'Penetration mode off.') {
            throw new Error('宿主未返回可核验状态；请重载 awa-ddd 插件');
          }
          const active = text === 'Penetration mode on.';
          if (!disposed) {
            states.set(sessionId, active);
            if (states.size > 128) states.delete(states.keys().next().value);
          }
          return active;
        })();
        pendingReads.set(sessionId, promise);
        const clear = () => { if (pendingReads.get(sessionId) === promise) pendingReads.delete(sessionId); };
        promise.then(clear, clear);
        return promise;
      };

      const refreshSession = () => {
        if (disposed) return;
        const sessionId = readSession();
        if (sessionId === currentSession) return;
        currentSession = sessionId;
        lastError = '';
        clearTimeout(errorTimer);
        paint();
        if (sessionId) readState(sessionId).then(() => {
          if (sessionId === currentSession) paint();
        }, error => fail(error, sessionId));
      };

      const toggle = async () => {
        if (disposed || busy) return;
        refreshSession();
        const sessionId = currentSession;
        if (!sessionId) { fail('请先打开一个会话'); return; }
        busy = true;
        lastError = '';
        clearTimeout(errorTimer);
        paint();
        try {
          const active = await readState(sessionId);
          if (disposed || readSession() !== sessionId) return;
          await execute(sessionId, active ? '/penetration off' : '/penetration');
          if (disposed) return;
          await readState(sessionId);
          mark('awaDddToggle', 'confirmed');
        } catch (error) {
          mark('awaDddToggle', 'rejected');
          fail(error, sessionId);
        } finally {
          busy = false;
          refreshSession();
          paint();
        }
      };

      const mount = () => {
        if (disposed || document.getElementById(BUTTON_ID) || !document.body) return;
        button = document.createElement('button');
        button.id = BUTTON_ID;
        button.type = 'button';
        button.className = 'awa-pen-btn';
        button.style.cssText = 'position:fixed;right:24px;bottom:96px;z-index:2147483000;height:30px;padding:0 14px;border-radius:999px;border:1px solid rgba(127,127,127,.45);background:var(--dsw-specific-menu,rgba(30,30,30,.92));color:inherit;font:inherit;font-size:13px;cursor:pointer;box-shadow:0 2px 10px rgba(0,0,0,.28)';
        button.addEventListener('click', toggle);
        document.body.appendChild(button);
        if (document.head && !document.getElementById(STYLE_ID)) {
          style = document.createElement('style');
          style.id = STYLE_ID;
          style.textContent = '.awa-pen-btn:disabled{opacity:.55;cursor:wait}.awa-pen-btn[data-active="true"]{font-weight:600}.awa-pen-btn[data-error="true"]{border-color:#c0392b}';
          document.head.appendChild(style);
        }
        paint();
        refreshSession();
        if (typeof window.MutationObserver === 'function') {
          observer = new window.MutationObserver(refreshSession);
          observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true,
            attributeFilter: ['data-conversation-session'] });
        }
        window.addEventListener?.('popstate', refreshSession);
        window.addEventListener?.('hashchange', refreshSession);
      };

      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true });
      else mount();
      return () => {
        if (disposed) return;
        disposed = true;
        clearTimeout(errorTimer);
        observer?.disconnect();
        document.removeEventListener?.('DOMContentLoaded', mount);
        window.removeEventListener?.('popstate', refreshSession);
        window.removeEventListener?.('hashchange', refreshSession);
        button?.removeEventListener('click', toggle);
        if (button && document.getElementById(BUTTON_ID) === button) button.remove();
        if (style && document.getElementById(STYLE_ID) === style) style.remove();
        states.clear();
        pendingReads.clear();
      };
    }

    return {
      name: 'awa-ddd-penetration-mode',
      inject: ['locale', 'remote', 'remote.commands'],
      apply(ctx) {
        mark('awaDddBundle', 'loaded');
        try { ctx.effect(() => ctx.locale.register('awa-ddd.penetration', COPY), 'awa-ddd: mode copy'); }
        catch { /* The optional copy service never prevents mounting the control. */ }
        ctx.effect(() => installButton(ctx), 'awa-ddd: mode control');
      },
    };
  },
});
