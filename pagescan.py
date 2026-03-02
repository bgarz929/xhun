import asyncio
import aiohttp
import uvloop
import random
import time

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

BASE_URL = "https://hashkeys.space/71/?page="
TARGET = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

CONCURRENT = 3   # TURUNKAN!
MAX_RETRY = 5

pages_scanned = 0


def fast_parse(html):
    if TARGET in html:
        for line in html.split("\n"):
            if TARGET in line:
                return line.strip().split()[0]
    return None


async def fetch(session, semaphore, page):
    global pages_scanned

    url = BASE_URL + str(page)
    retry = 0

    while retry < MAX_RETRY:

        async with semaphore:
            try:
                async with session.get(url) as resp:

                    if resp.status == 429:
                        retry_after = resp.headers.get("Retry-After")
                        wait = int(retry_after) if retry_after else (2 ** retry)
                        print(f"429 → Backing off {wait}s")
                        await asyncio.sleep(wait)
                        retry += 1
                        continue

                    if resp.status != 200:
                        return None

                    html = await resp.text()
                    pages_scanned += 1

                    return fast_parse(html)

            except Exception as e:
                await asyncio.sleep(2)
                retry += 1

    return None


async def main():

    semaphore = asyncio.Semaphore(CONCURRENT)

    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (X11; Linux x86_64)"
        ])
    }

    async with aiohttp.ClientSession(headers=headers) as session:

        for page in range(1, 50):   # JANGAN BESAR DULU
            result = await fetch(session, semaphore, page)

            print(f"Page {page} scanned | Total: {pages_scanned}")

            await asyncio.sleep(random.uniform(0.5, 1.5))  # delay human-like

            if result:
                print("FOUND:", result)
                break


if __name__ == "__main__":
    asyncio.run(main())
