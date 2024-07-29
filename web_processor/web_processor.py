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
        return 'recaptcha v3'
    

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
            data["clientKey"] = self.my_key
            if self.proxy:
                data["task"]["proxyType"] = self.proxy.split('://')[0]
                data["task"]["proxyAddress"] = self.proxy.split('://')[1].split(':')[0]
                data["task"]["proxyPort"] = self.proxy.split('://')[1].split(':')[1]
                # data["task"]["proxyLogin"]
                # data["task"]["proxyPassword"]
            else:
                data["task"]["type"] += 'Proxyless'
            print(data)
            async with session.post("https://api.2captcha.com/createTask", json=data) as response:
                response_text = await response.text()
                print("Request sent", response_text)
                response_json = await response.json()
            data["taskId"] = response_json.get("taskId")
            while True:
                async with session.post(f"https://api.2captcha.com/getTaskResult", json=data) as solution_response:
                    solution = await solution_response.json()
                    print(f'{solution=}')
                    if solution["status"] == "processing":
                        print('Processing...')
                        await asyncio.sleep(8)
                    elif solution["errorId"] != 0:
                        print(solution)
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
                    "clientKey": self.my_key,
                    "task": {
                        "type": "TurnstileTask",
                        "websiteURL": url,
                        "websiteKey": params["sitekey"],
                        "action": "managed",
                        "data": params["data"],
                        "pagedata": params["pagedata"],
                        "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    }
                }
                print(data)
                solution = await self.protect_break(data)
                if solution.get("errorId", -1) == 0:
                    token = solution['solution']['token']
                    await page.evaluate(f"cfCallback('{token}');")
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
                    "clientKey": self.my_key,
                    "task": {
                        "type": "TurnstileTask",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                        #  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
                    }
                }            
                solution = await self.protect_break(data)
                if solution.get("errorId", -1) == 0:
                    token = solution['solution']['token']
                    await page.evaluate("""async (token) => {
                        document.querySelector('[name="cf-turnstile-response"]').value = token;
                    }""", token)
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
                await page.wait_for_timeout(5000)
                data = {
                    "clientKey": self.my_key,
                    "task": {
                        "type": "RecaptchaV2Task",
                        "websiteURL": url,
                        "websiteKey": sitekey,
                    }
                }          
                solution = await self.protect_break(data)
                if solution.get("errorId", -1) == 0:
                    token = solution['solution']['gRecaptchaResponse']
                    await page.evaluate('''(token) => {
                        const textarea = document.getElementById('g-recaptcha-response');
                        textarea.value = token;
                    }''', token)
                    await page.wait_for_timeout(2000)
                    await page.click('button[type="submit"]')
                    await page.wait_for_timeout(4000)
                else:
                    await page.close()
                    await context.close()
                    return ''
                
            case 'recaptcha v3':
                params = dict()
                # Intercept requests to the reCAPTCHA API script
                async def intercept_request(request):
                    nonlocal params
                    if 'recaptcha/api.js' in request.url:
                        sitekey = request.url.split(r'?render=')[1]
                        print('Intercepted sitekey:', sitekey)
                        params['sitekey'] = sitekey

                page.on('request', intercept_request)                
                await page.reload()
                await page.wait_for_timeout(5000)
                data = {
                    "clientKey": self.my_key,
                    "task": {
                        "type": "RecaptchaV3Task",
                        "websiteURL": url,
                        "websiteKey": params['sitekey'],                      
                        "minScore": 0.3,
                    }
                }          
                solution = await self.protect_break(data)
                if solution.get("errorId", -1) == 0:
                    token = solution['solution']['gRecaptchaResponse']
                    await page.evaluate('''(token) => {
                        window.verifyRecaptcha(token);
                    }''', token)
                    await page.wait_for_timeout(4000)
                    # await page.click('button[type="submit"]')
                    # await page.wait_for_timeout(4000)
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
        # 'https://2captcha.com/demo/recaptcha-v2',
        'https://2captcha.com/demo/recaptcha-v3',
        # 'https://4pda.to/',
        # 'https://ipinfo.io/'
    ]
    
    wp = WebProcessor(proxy='')
    page_contents = await wp.fetch_pages(urls)

    for content in page_contents:
        if isinstance(content, Exception):
            print(f"Error occurred: {content}")
        else:
            ...
            # print(content)

asyncio.run(main())
