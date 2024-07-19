import requests
from seleniumbase import Driver
from selenium.webdriver.common.by import By
import time
import re
import time
import json
import keyring
my_key = keyring.get_password('2captcha', 'default')


# Function to intercept CAPTCHA parameters using JavaScript
def intercept(driver):
    driver.execute_script("""
    console.clear = () => console.log('Console was cleared')
    const i = setInterval(()=>{
    if (window.turnstile)
     console.log('success!!')
     {clearInterval(i)
         window.turnstile.render = (a,b) => {
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
            return        } 
    }
},50)    
""")
    time.sleep(1)
    # Retrieving browser logs containing intercepted parameters
    logs = driver.get_log("browser")
    for log in logs:
        if log['level'] == 'INFO':
            if "intercepted-params:" in log["message"]:
                log_entry = log["message"].encode('utf-8').decode('unicode_escape')
                match = re.search(r'"intercepted-params:({.*?})"', log_entry)
                json_string = match.group(1)
                params = json.loads(json_string)
                return params

# Setting up an updated UserAgent
agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"

# Configuring the web driver to work in headless mode
driver = Driver(uc=True, log_cdp=True, headless=True, no_sandbox=True, agent=agent, proxy=False)

# URL of the website protected by the Turnstile CAPTCHA

url = 'https://2captcha.com/demo/cloudflare-turnstile-challenge'
driver.get(url)
driver.refresh()
params = intercept(driver)
(print(params))
driver.sleep(10)


data0 = {"key": my_key,
         "method": "turnstile ",
         "sitekey": params["sitekey"],
         "action": params["action"],
         "data": params["data"],
         "pagedata": params["pagedata"],
         "useragent": params["userAgent"],
         "json": 1,
         "pageurl": params["pageurl"],
         }
response = requests.post(f"https://2captcha.com/in.php?", data=data0)
print("Request sent", response.text)
s = response.json()["request"]

while True:
    solu = requests.get(f"https://2captcha.com/res.php?key={my_key}&action=get&json=1&id={s}").json()
    if solu["request"] == "CAPCHA_NOT_READY":
        print(solu["request"])
        time.sleep(8)
    elif "ERROR" in solu["request"]:
        print(solu["request"])
        driver.close()
        driver.quit()
        exit(0)
    else:
        break

for key, value in solu.items():
    print(key, ": ", value)

solu = solu['request']
driver.execute_script(f" cfCallback('{solu}');")
time.sleep(5)

src = driver.page_source
print(src)

driver.close()
driver.quit()