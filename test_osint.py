import asyncio
import aiohttp

async def fetch_real_threats():
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get("https://isc.sans.edu/api/sources/attacks/10?json") as response:
                print(f"Status: {response.status}")
                if response.status == 200:
                    data = await response.json(content_type=None)
                    ips = [item['ip'] for item in data if 'ip' in item]
                    print(f"Fetched {len(ips)} IPs: {ips}")
                else:
                    text = await response.text()
                    print(f"Failed. Response: {text}")
    except Exception as e:
        print(f"Error fetching threats: {e}")

asyncio.run(fetch_real_threats())
