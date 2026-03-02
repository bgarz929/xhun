import asyncio
import aiohttp
import uvloop
import random
import time
import signal

# Aktifkan uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

BASE_URL = "https://hashkeys.space/71/"
TARGET = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

START_PAGE = 1
END_PAGE = 2000
CONCURRENT = 200
RANDOM_MODE = False   # True = random sampling

found_event = asyncio.Event()
pages_scanned = 0


def fast_parse(html):
    # parsing super cepat (tanpa bs4 / regex)
    lines = html.split("\n")
    for line in lines:
        if TARGET in line:
            parts = line.strip().split()
            if len(parts) >= 2:
                return parts[0]
    return None


async def fetch(session, semaphore, page):
    global pages_scanned

    if found_event.is_set():
        return None

    async with semaphore:
        try:
            async with session.get(BASE_URL + str(page), timeout=6) as resp:
                if resp.status != 200:
                    return None

                html = await resp.text()
                pages_scanned += 1

                key_hex = fast_parse(html)
                if key_hex:
                    found_event.set()
                    return (page, key_hex)

        except:
            return None

    return None


async def speed_monitor():
    global pages_scanned
    prev = 0
    while not found_event.is_set():
        await asyncio.sleep(1)
        current = pages_scanned
        print(f"Speed: {current - prev} pages/sec | Total: {current}")
        prev = current


async def main():

    semaphore = asyncio.Semaphore(CONCURRENT)

    connector = aiohttp.TCPConnector(
        limit=CONCURRENT,
        ttl_dns_cache=600,
        enable_cleanup_closed=True
    )

    headers = {"User-Agent": "Mozilla/5.0"}

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers
    ) as session:

        monitor_task = asyncio.create_task(speed_monitor())

        if RANDOM_MODE:
            tasks = [
                asyncio.create_task(
                    fetch(session, semaphore, random.randint(1, 10_000_000))
                )
                for _ in range(5000)
            ]
        else:
            tasks = [
                asyncio.create_task(fetch(session, semaphore, p))
                for p in range(START_PAGE, END_PAGE + 1)
            ]

        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                page, key_hex = result
                print("\nFOUND!")
                print("Page:", page)
                print("Private key:", key_hex)
                break

        monitor_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
