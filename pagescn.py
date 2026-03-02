import asyncio
import aiohttp
import uvloop
import time

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

BASE_URL = "https://hashkeys.space/71/?page="
TARGET = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"

START_PAGE = 1
END_PAGE = 200
CONCURRENT = 20

found_event = asyncio.Event()
pages_scanned = 0


def fast_parse(html):
    if TARGET in html:
        for line in html.split("\n"):
            if TARGET in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    return parts[0]
    return None


async def fetch(session, semaphore, page):
    global pages_scanned

    if found_event.is_set():
        return None

    url = BASE_URL + str(page)

    async with semaphore:
        try:
            async with session.get(url, timeout=10) as resp:
                print(f"Page {page} → Status {resp.status}")

                if resp.status != 200:
                    return None

                html = await resp.text()
                pages_scanned += 1

                key_hex = fast_parse(html)
                if key_hex:
                    found_event.set()
                    return (page, key_hex)

        except Exception as e:
            print("ERROR:", e)

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

    connector = aiohttp.TCPConnector(limit=CONCURRENT)

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html"
    }

    async with aiohttp.ClientSession(
        connector=connector,
        headers=headers
    ) as session:

        monitor_task = asyncio.create_task(speed_monitor())

        tasks = [
            asyncio.create_task(fetch(session, semaphore, p))
            for p in range(START_PAGE, END_PAGE + 1)
        ]

        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                print("\nFOUND:", result)
                break

        monitor_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
