from playwright.async_api import async_playwright, expect
from browserforge.injectors.playwright import AsyncNewContext
from browserforge.fingerprints import FingerprintGenerator
import re
import json
import asyncio
import keyring
import aiohttp

class WebProcessor:

    def __init__(self, proxy='socks5://127.0.0.1:2080'):
        self.playwright = None
        self.browser = None
        self.proxy = proxy
        self.fingerprints = FingerprintGenerator()
        self.my_key = keyring.get_password('2captcha', 'default')

    async def initialize(self):
        self.playwright = await async_playwright().start()
        if self.proxy:
            self.browser = await self.playwright.chromium.launch(proxy={'server': self.proxy})
        else:
            self.browser = await self.playwright.chromium.launch()
                   
    async def close(self):
        await self.browser.close()
        await self.playwright.stop()

    async def fetch_pages(self, urls):
        await self.initialize()
        tasks = [self.get_page(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        await self.close()
        return results

    def filename_check(self, filename): return ''.join(list(map(lambda x: '' if x in r'\/:*?"<>|' or x == '\n' else x, filename)))[:128]


    async def detect_protect(self, content):
        if 'https://challenges.cloudflare.com/turnstile' in content:
            if 'challenge-success-text' in content:
                return 'cloudflare challenges'
            else:
                return 'cloudflare turnstile'
        if 'recaptcha' in content:
            if 'I\'m not a robot' in content:
                return 'recaptcha v2'
            elif 'captchaWidgetContainer' in content:
                return 'recaptcha v3'
        return ''
    
    async def protect_break(self, data):
        async with aiohttp.ClientSession() as session:
            solution = dict()
            async with session.post("https://2captcha.com/in.php", data=data) as response:
                response_text = await response.text()
                print("Request sent", response_text)
                response_json = await response.json()
                s = response_json["request"]
            while True:
                async with session.get(f"https://2captcha.com/res.php?key={self.my_key}&action=get&json=1&id={s}") as solution_response:
                    solution = await solution_response.json()
                    if solution["request"] == "CAPCHA_NOT_READY":
                        print(solution["request"])
                        await asyncio.sleep(8)
                    elif "ERROR" in solution["request"]:
                        print(solution["request"])
                        break
                    else:
                        break
            print(f'{solution=}')
            return solution


    async def get_page(self, url='', protect_type=''):
        content = ''
        print(f'get_page {url} started...')
        fingerprint = self.fingerprints.generate()
        context = await AsyncNewContext(self.browser, fingerprint=fingerprint)
        page = await context.new_page()
        await page.goto(url)
        # await page.reload()
        # await page.wait_for_timeout(10000)
        content = await page.content()
        protect_type = await self.detect_protect(content)

        print(f'Detected protect type: {protect_type} ({url})')

        match protect_type:

            case 'cloudflare challenges':
                params = dict()
                async def handle_console_message(msg):
                    nonlocal params
                    if msg.type == 'log' and 'intercepted-params' in msg.text:
                        match = re.search(r'intercepted-params:(\{.*\})', msg.text)
                        if match:
                            params = json.loads(match.group(1))
                page.on('console', handle_console_message)
                await page.reload()
                await page.evaluate("""async () => {
                    console.clear = () => console.log('Console was cleared')
                    const i = setInterval(() => {
                        if (window.turnstile) {
                            console.log('success!!')
                            clearInterval(i)
                            window.turnstile.render = (a, b) => {
                                let params = {
                                    sitekey: b.sitekey,
                                    pageurl: window.location.href,
                                    data: b.cData,
                                    pagedata: b.chlPageData,
                                    action: b.action,
                                    userAgent: navigator.userAgent,
                                    json: 1
                                }
                                console.log('intercepted-params:' + JSON.stringify(params))
                                window.cfCallback = b.callback
                                return
                            }
                        }
                    }, 50)
                }""")
                # await page.evaluate("console.log('TEST MSG')")
                await page.wait_for_timeout(10000)
                data = {
                    "key": self.my_key,
                    "method": "turnstile",
                    "sitekey": params["sitekey"],
                    "action": params["action"],
                    "data": params["data"],
                    "pagedata": params["pagedata"],
                    "useragent": params["userAgent"],
                    "json": 1,
                    "pageurl": params["pageurl"],
                }
                solution = await self.protect_break(data)
                if solution:
                    await page.evaluate(f"cfCallback('{solution['''request''']}');")
                    await page.wait_for_timeout(5000)
                else:             
                    await page.close()
                    await context.close()
                    return ''

            case 'cloudflare turnstile':
                await page.reload()
                # await page.evaluate("console.log('TEST MSG')")
                await page.wait_for_timeout(2000)
                sitekey = await page.evaluate('''() => {
                        const cloudflareElement = document.querySelector('.cf-turnstile');
                        return cloudflareElement ? cloudflareElement.getAttribute('data-sitekey') : null;
                    }''')                
                data = {
                    "key": self.my_key,
                    "method": "turnstile",
                    "sitekey": sitekey,
                    "json": 1,
                    "pageurl": url,
                }
                solution = await self.protect_break(data)
                if solution:
                    await page.evaluate("""async (solution) => {
                        document.querySelector('[name="cf-turnstile-response"]').value = solution['request'];
                    }""", solution)
                    await page.wait_for_timeout(2000)
                    await page.click('button[type="submit"]')
                    await page.wait_for_timeout(4000)
                else:
                    await page.close()
                    await context.close()
                    return ''

            case 'recaptcha v2':
                await page.goto(url)
                sitekey = await page.evaluate('''() => {
                    const recaptchaElement = document.querySelector('.g-recaptcha');
                    return recaptchaElement ? recaptchaElement.getAttribute('data-sitekey') : null;
                }''')
                if sitekey:
                    print(f"Sitekey: {sitekey}")
                else:
                    print("Recaptcha element not found")
                await page.wait_for_timeout(5000)
                data = {
                    "key": self.my_key,
                    "method": "userrecaptcha",
                    "googlekey": sitekey,
                    "invisible": 0,
                    "enterprise": 0,
                    "version": "v2",
                    "pageurl": url,
                    "json": 1
                }              
                solution = await self.protect_break(data)
                if solution:
                    await page.evaluate('''(token) => {
                        const textarea = document.getElementById('g-recaptcha-response');
                        textarea.value = token;
                    }''', solution['request'])
                    await page.wait_for_timeout(2000)
                    await page.click('button[type="submit"]')
                    await page.wait_for_timeout(4000)
                else:
                    await page.close()
                    await context.close()
                    return ''
            case _:
                ...   

        content = await page.content()
        await page.screenshot(path=f'{self.filename_check(url.split("://")[1])}.png')
        await page.close()
        await context.close()
        print(f'get_page {url} finished ({round(len(content)/1024)} KB received)')
        return content


async def main():
    urls = [
        # 'https://2captcha.com/demo/cloudflare-turnstile-challenge',
        # 'https://2captcha.com/demo/cloudflare-turnstile',
        'https://2captcha.com/demo/recaptcha-v2',
        # 'https://2captcha.com/demo/recaptcha-v3',
        # 'https://4pda.to/',
        # 'https://ipinfo.io/'
    ]
    
    wp = WebProcessor()
    page_contents = await wp.fetch_pages(urls)

    for content in page_contents:
        if isinstance(content, Exception):
            print(f"Error occurred: {content}")
        else:
            ...
            # print(content)

asyncio.run(main())
