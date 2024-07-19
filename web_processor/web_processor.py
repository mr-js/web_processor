from playwright.async_api import async_playwright, expect
from browserforge.injectors.playwright import AsyncNewContext
from browserforge.fingerprints import FingerprintGenerator
import re
import json
import asyncio
import keyring
import aiohttp

class WebProcessor:

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.fingerprints = FingerprintGenerator()
        self.my_key = keyring.get_password('2captcha', 'default')

    async def initialize(self):
        self.playwright = await async_playwright().start()
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

    async def get_page(self, url='', protect_type='turnstile'):
        content = ''
        print(f'get_page {url} started...')
        fingerprint = self.fingerprints.generate()
        context = await AsyncNewContext(self.browser, fingerprint=fingerprint)
        page = await context.new_page()

        await page.goto(url)

        match protect_type:
            case 'turnstile':
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
                data0 = {
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
                async with aiohttp.ClientSession() as session:
                    async with session.post("https://2captcha.com/in.php", data=data0) as response:
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
                                await page.close()
                                await context.close()
                                return content
                            else:
                                break
                    solution_request = solution['request']
                    await page.evaluate(f"cfCallback('{solution_request}');")
                    await page.wait_for_timeout(5000)
            case _:
                ...   

        await page.screenshot(path=f'{self.filename_check(url.split("://")[1])}.png')
        content = await page.content()
        await page.close()
        await context.close()
        print(f'get_page {url} finished ({round(len(content)/1024)} KB received)')
        return content


async def main():
    urls = [
        'https://2captcha.com/demo/cloudflare-turnstile-challenge',
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
