import asyncio
from fastmcp import Client

client = Client("http://localhost:8000/mcp")

async def call_tool(arg:str):
    async with client:
        result = await client.call_tool("cpp_test", {"message": arg})
        print(result)

asyncio.run(call_tool("Hello, World!"))