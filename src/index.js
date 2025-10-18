import { SingboxConfigBuilder } from './SingboxConfigBuilder.js';
import { generateHtml } from './htmlBuilder.js';
import { ClashConfigBuilder } from './ClashConfigBuilder.js';
import { SurgeConfigBuilder } from './SurgeConfigBuilder.js';
import { decodeBase64, encodeBase64, GenerateWebPath, sha256 } from './utils.js';
import { PREDEFINED_RULE_SETS, SING_BOX_CONFIG, CLASH_CONFIG } from './config.js';
import { t, setLanguage } from './i1n/index.js';
import yaml from 'js-yaml';
import {
    initDatabase, getSettings, updateSettings, getAdminPassword, setAdminPassword,
    getWhitelistedDomains, addWhitelistedDomain, removeWhitelistedDomain, isDomainWhitelisted,
    createShortlink, getShortlink
} from './db.js';
import {
    generateAdminLoginPage, generateSetupPage, generateD1BindingGuidePage, generateAdminPanel
} from './admin.js';
import { generateEmbedHtml } from './embed.js';

const cookieName = 'auth-token';

async function verifySourceDomains(db, configString, settings) {
    if (settings.whitelist_enabled !== 'true') {
        return { allowed: true };
    }
    const sourceUrls = configString.split('\n').filter(line => line.trim().startsWith('http'));
    if (sourceUrls.length === 0) return { allowed: true };
    const allowedDomains = new Set(await getWhitelistedDomains(db));
    if (allowedDomains.size === 0) return { allowed: false, reason: 'Whitelist is enabled, but no domains have been added.' };
    const sourceDomains = new Set(sourceUrls.map(u => { try { return new URL(u).hostname } catch(e) { return null } }).filter(Boolean));
    for (const domain of sourceDomains) {
        if (!allowedDomains.has(domain)) {
            return { allowed: false, reason: `Source domain not allowed: ${domain}` };
        }
    }
    return { allowed: true };
}

async function handleRequest(request, env, ctx) {
    if (!env.DB) return new Response(generateD1BindingGuidePage(), { status: 503, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    
    ctx.waitUntil(initDatabase(env.DB));
    const adminPassword = await getAdminPassword(env.DB);
    const url = new URL(request.url);

    if (!adminPassword && url.pathname !== '/setup') return Response.redirect(`${url.origin}/setup`, 302);
    if (url.pathname.startsWith('/setup')) return handleSetup(request, env.DB, adminPassword);
    if (url.pathname.startsWith('/admin')) return handleAdmin(request, env.DB);
    if (url.pathname.startsWith('/api/admin')) return handleAdminApi(request, env.DB);
    
    const settings = await getSettings(env.DB);
    const lang = url.searchParams.get('lang');
    setLanguage(lang || request.headers.get('accept-language')?.split(',')[0]);

    if (url.pathname === '/bing-wallpaper') {
        const imageUrl = 'https://www.bing.com/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=zh-CN';
        try {
            const imageResponse = await fetch(imageUrl);
            const imageData = await imageResponse.json();
            const wallpaperUrl = 'https://www.bing.com' + imageData.images[0].url;
            return fetch(wallpaperUrl);
        } catch (e) {
            return new Response('Failed to fetch wallpaper', { status: 502 });
        }
    }

    if (url.pathname === '/embed') {
        if (settings.api_enabled !== 'true') return new Response('API is disabled.', { status: 403 });
        const isAllowed = await isDomainWhitelisted(env.DB, request.headers.get('Referer'));
        if (!isAllowed) return new Response('Not authorized.', { status: 403 });
        return new Response(generateEmbedHtml(url.origin), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    
    if (request.method === 'GET' && url.pathname === '/') {
      return new Response(generateHtml('', '', '', '', url.origin, settings), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    
    if (url.pathname.startsWith('/singbox') || url.pathname.startsWith('/clash') || url.pathname.startsWith('/surge') || url.pathname.startsWith('/xray')) {
      const inputString = url.searchParams.get('config');
      if (!inputString) return new Response(t('missingConfig'), { status: 400 });
      const verification = await verifySourceDomains(env.DB, inputString, settings);
      if (!verification.allowed) return new Response(verification.reason, { status: 403 });
      
      if (url.pathname.startsWith('/xray')) {
        const proxylist = inputString.split('\n');
        const finalProxyList = [];
        let userAgent = url.searchParams.get('ua') || settings.default_user_agent || 'curl/7.74.0';
        let headers = new Headers({ "User-Agent": userAgent });
        for (const proxy of proxylist) {
          if (proxy.startsWith('http')) {
            try {
              const response = await fetch(proxy, { method: 'GET', headers: headers });
              const text = await response.text();
              let decodedText = decodeBase64(text.trim());
              if (decodedText.includes('%')) decodedText = decodeURIComponent(decodedText);
              finalProxyList.push(...decodedText.split('\n'));
            } catch (e) { console.warn('Failed to fetch the proxy:', e); }
          } else {
            finalProxyList.push(proxy);
          }
        }
        const finalString = finalProxyList.join('\n');
        if (!finalString) return new Response('Missing config parameter', { status: 400 });
        return new Response(encodeBase64(finalString), { headers: { 'content-type': 'text/plain; charset=utf-8' } });
      }

      let selectedRules = url.searchParams.get('selectedRules') || settings.default_ruleset;
      let customRulesParam = url.searchParams.get('customRules');
      let userAgent = url.searchParams.get('ua') || settings.default_user_agent;
      let langParam = url.searchParams.get('lang') || 'zh-CN';
      let customRules;
      try { selectedRules = JSON.parse(decodeURIComponent(selectedRules)); } catch (e) {}
      try { customRules = customRulesParam ? JSON.parse(decodeURIComponent(customRulesParam)) : JSON.parse(settings.default_custom_rules); } catch (error) { customRules = []; }
      
      let baseConfig;
      if (url.pathname.startsWith('/singbox')) {
        try { baseConfig = settings.default_base_config_singbox ? JSON.parse(settings.default_base_config_singbox) : null; } catch(e) { baseConfig = null; }
        if (!baseConfig) { baseConfig = SING_BOX_CONFIG; }
      } else if (url.pathname.startsWith('/clash')) {
        try { baseConfig = settings.default_base_config_clash ? yaml.load(settings.default_base_config_clash) : null; } catch(e) { baseConfig = null; }
        if (!baseConfig) { baseConfig = CLASH_CONFIG; }
      }

      let configBuilder;
      if (url.pathname.startsWith('/singbox')) {
        configBuilder = new SingboxConfigBuilder(inputString, selectedRules, customRules, baseConfig, langParam, userAgent);
      } else if (url.pathname.startsWith('/clash')) {
        configBuilder = new ClashConfigBuilder(inputString, selectedRules, customRules, baseConfig, langParam, userAgent);
      } else {
        configBuilder = new SurgeConfigBuilder(inputString, selectedRules, customRules, baseConfig, langParam, userAgent).setSubscriptionUrl(url.href);
      }

      const config = await configBuilder.build();
      const headers = { 'content-type': url.pathname.startsWith('/singbox') ? 'application/json; charset=utf-8' : url.pathname.startsWith('/clash') ? 'text/yaml; charset=utf-8' : 'text/plain; charset=utf-8' };
      if (url.pathname.startsWith('/surge')) headers['subscription-userinfo'] = 'upload=0; download=0; total=10737418240; expire=2546249531';
      return new Response(url.pathname.startsWith('/singbox') ? JSON.stringify(config, null, 2) : config, { headers });
    } 
    
    if (url.pathname === '/shorten-v2') {
        if (settings.api_enabled !== 'true') return new Response('API is disabled.', { status: 403 });
        const isAllowed = await isDomainWhitelisted(env.DB, request.headers.get('Referer'));
        if (!isAllowed) return new Response('Not authorized.', { status: 403 });
        const originalUrl = url.searchParams.get('url');
        let shortCode = url.searchParams.get('shortCode');
        if (!originalUrl) return new Response('Missing URL parameter', { status: 400 });
        const queryString = new URL(originalUrl).search;
        if (!shortCode) shortCode = GenerateWebPath();
        await createShortlink(env.DB, shortCode, queryString);
        return new Response(shortCode, { headers: { 'Content-Type': 'text/plain' } });
    }
    
    if (url.pathname.startsWith('/b/') || url.pathname.startsWith('/c/') || url.pathname.startsWith('/x/') || url.pathname.startsWith('/s/')) {
        const shortCode = url.pathname.split('/')[2];
        const originalParam = await getShortlink(env.DB, shortCode);
        if (originalParam === null) return new Response(t('shortUrlNotFound'), { status: 404 });
        let redirectPath;
        if (url.pathname.startsWith('/b/')) redirectPath = 'singbox';
        else if (url.pathname.startsWith('/c/')) redirectPath = 'clash';
        else if (url.pathname.startsWith('/x/')) redirectPath = 'xray';
        else if (url.pathname.startsWith('/s/')) redirectPath = 'surge';
        else return new Response(t('notFound'), { status: 404 });
        return Response.redirect(`${url.origin}/${redirectPath}${originalParam}`, 302);
    }
    
    if (url.pathname === '/favicon.ico') return Response.redirect('https://icon-icons.com/icon/horror-crow-bird-raven-halloween/229333', 301);
    
    // --- START: NEW UNIVERSAL SUBSCRIPTION API LOGIC ---
    try {
        let subUrl = url.pathname.slice(1);
        if (url.search) {
            subUrl += url.search;
        }

        if (!subUrl.startsWith('http://') && !subUrl.startsWith('https://')) {
            subUrl = 'https://' + subUrl;
        }

        new URL(subUrl);

        const requestUserAgent = request.headers.get('User-Agent') || '';
        let targetClient = 'clash';
        
        if (/clash|stash|meta/i.test(requestUserAgent)) {
            targetClient = 'clash';
        } else if (/sing-box|nekoray|nekobox/i.test(requestUserAgent)) {
            targetClient = 'sing-box';
        } else if (/surge/i.test(requestUserAgent)) {
            targetClient = 'surge';
        } else if (/v2ray|shadowrocket|v2box/i.test(requestUserAgent)) {
            targetClient = 'xray';
        }
        
        const inputString = subUrl;
        const verification = await verifySourceDomains(env.DB, inputString, settings);
        if (!verification.allowed) return new Response(verification.reason, { status: 403 });

        if (targetClient === 'xray') {
            const proxylist = inputString.split('\n');
            const finalProxyList = [];
            let fetchUserAgent = settings.default_user_agent || 'curl/7.74.0';
            let headers = new Headers({ "User-Agent": fetchUserAgent });
            for (const proxy of proxylist) {
                if (proxy.startsWith('http')) {
                    try {
                        const response = await fetch(proxy, { method: 'GET', headers: headers });
                        const text = await response.text();
                        let decodedText = decodeBase64(text.trim());
                        if (decodedText.includes('%')) decodedText = decodeURIComponent(decodedText);
                        finalProxyList.push(...decodedText.split('\n'));
                    } catch (e) { console.warn('Failed to fetch the proxy:', e); }
                } else {
                    finalProxyList.push(proxy);
                }
            }
            const finalString = finalProxyList.join('\n');
            if (!finalString) return new Response('Could not resolve a valid proxy list from the URL.', { status: 400 });
            return new Response(encodeBase64(finalString), { headers: { 'content-type': 'text/plain; charset=utf-8' } });
        }

        let selectedRules = settings.default_ruleset;
        let customRules;
        try { customRules = JSON.parse(settings.default_custom_rules); } catch (error) { customRules = []; }
        
        let subFetchingUserAgent = settings.default_user_agent;
        let langForRules = settings.default_lang || 'zh-CN';

        let baseConfig;
        if (targetClient === 'sing-box') {
            try { baseConfig = settings.default_base_config_singbox ? JSON.parse(settings.default_base_config_singbox) : null; } catch (e) { baseConfig = null; }
            if (!baseConfig) { baseConfig = SING_BOX_CONFIG; }
        } else if (targetClient === 'clash') {
            try { baseConfig = settings.default_base_config_clash ? yaml.load(settings.default_base_config_clash) : null; } catch (e) { baseConfig = null; }
            if (!baseConfig) { baseConfig = CLASH_CONFIG; }
        }

        let configBuilder;
        if (targetClient === 'sing-box') {
            configBuilder = new SingboxConfigBuilder(inputString, selectedRules, customRules, baseConfig, langForRules, subFetchingUserAgent);
        } else if (targetClient === 'clash') {
            configBuilder = new ClashConfigBuilder(inputString, selectedRules, customRules, baseConfig, langForRules, subFetchingUserAgent);
        } else { // surge
            configBuilder = new SurgeConfigBuilder(inputString, selectedRules, customRules, baseConfig, langForRules, subFetchingUserAgent).setSubscriptionUrl(url.href);
        }

        const config = await configBuilder.build();
        const headers = { 'content-type': targetClient === 'sing-box' ? 'application/json; charset=utf-8' : targetClient === 'clash' ? 'text/yaml; charset=utf-8' : 'text/plain; charset=utf-8' };
        if (targetClient === 'surge') {
            headers['subscription-userinfo'] = 'upload=0; download=0; total=10737418240; expire=2546249531';
        }
        return new Response(targetClient === 'sing-box' ? JSON.stringify(config, null, 2) : config, { headers });

    } catch (error) {
        // Fall through to 404 if the path is not a valid URL
    }
    // --- END: NEW UNIVERSAL SUBSCRIPTION API LOGIC ---

    return new Response(t('notFound'), { status: 404 });
}

async function handleSetup(request, db, adminPassword) {
    if (adminPassword) return Response.redirect(new URL(request.url).origin, 302);
    if (request.method === 'POST') {
        const formData = await request.formData();
        const password = formData.get('password');
        const confirmPassword = formData.get('confirm_password');
        if (password && password === confirmPassword) {
            await setAdminPassword(db, await sha256(password));
            return Response.redirect(new URL(request.url).origin + '/admin', 302);
        }
        return new Response('Passwords do not match.', { status: 400 });
    }
    return new Response(generateSetupPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

async function verifyAuth(request, db) {
    const cookie = request.headers.get('Cookie');
    if (!cookie || !cookie.includes(cookieName)) return false;
    const token = cookie.split(';').find(c => c.trim().startsWith(cookieName)).split('=')[1];
    const adminPassword = await getAdminPassword(db);
    return token === await sha256('LoggedIn-' + adminPassword);
}

async function handleAdmin(request, db) {
    const url = new URL(request.url);
    if (url.pathname === '/admin/login') {
        if (request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get('password');
            const adminPassword = await getAdminPassword(db);
            if (adminPassword && await sha256(password) === adminPassword) {
                const token = await sha256('LoggedIn-' + adminPassword);
                const headers = new Headers({ 'Set-Cookie': `${cookieName}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict`, 'Location': '/admin' });
                return new Response(null, { status: 302, headers });
            }
            return new Response(generateAdminLoginPage('密码错误'), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
        }
        return new Response(generateAdminLoginPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    const isAuthed = await verifyAuth(request, db);
    if (!isAuthed) return Response.redirect(`${url.origin}/admin/login`, 302);
    const settings = await getSettings(db);
    const domains = await getWhitelistedDomains(db);
    return new Response(generateAdminPanel(settings, domains), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

async function handleAdminApi(request, db) {
    const isAuthed = await verifyAuth(request, db);
    if (!isAuthed) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    const url = new URL(request.url);
    if (request.method !== 'POST') return new Response('Method not allowed', { status: 405 });
    const data = await request.json();
    if (url.pathname === '/api/admin/settings') {
        await updateSettings(db, data);
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    } else if (url.pathname === '/api/admin/whitelist/add') {
        await addWhitelistedDomain(db, data.domain);
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    } else if (url.pathname === '/api/admin/whitelist/remove') {
        await removeWhitelistedDomain(db, data.domain);
        return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('Not found', { status: 404 });
}

export default {
    async fetch(request, env, ctx) {
        try {
            return await handleRequest(request, env, ctx);
        } catch (error) {
            console.error('Error processing request:', error);
            return new Response(t('internalError') + `: ${error.message}`, { status: 500 });
        }
    }
};
