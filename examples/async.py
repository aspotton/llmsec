import asyncio

from llmsec import Guard


async def main() -> None:
    guard = Guard.default()
    result = await guard.ainspect_retrieval("A normal retrieved document.")
    print(result.action)


if __name__ == "__main__":
    asyncio.run(main())
