#!/usr/bin/python3

import time

limit = 15           # in gigabytes
size_x = 4          # number of kilobytes
to_alloc = 1024     # number of blocks to alloc per iteration

block_size = (1024) * size_x    # 1 kib x multiplier

allocated = []
total_blocks = 0
total_gib_size = 0

while total_gib_size <= limit:
    try:
        add_bytes = block_size * to_alloc

        total_blocks += add_bytes/block_size
        total_gib_size += ( ( (add_bytes / 1024 ) / 1024 ) / 1024 )

        iteralloc = bytearray(add_bytes)
        allocated.append(iteralloc)

        print(f"Allocated: {total_blocks} blocks ({size_x} KiB), {total_gib_size:.2f} GiB")

        time.sleep(0.1)

    except MemoryError:
        print("\nMemory exceeded. Ouch!")

    except KeyboardInterrupt:
        print("\nMemory stress test ending...")
        break
