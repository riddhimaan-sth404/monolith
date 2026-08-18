"""Check format of each model file."""
from pathlib import Path

models = {
    'PE': Path(r'C:\Users\amin\Projects\EMBER2024-benchmark-models\EMBER2024_PE.model'),
    'PDF': Path(r'C:\Users\amin\Projects\EMBER2024-benchmark-models\EMBER2024_PDF.model'),
    'Dot_Net': Path(r'C:\Users\amin\Projects\EMBER2024-benchmark-models\EMBER2024_Dot_Net.model'),
    'exploit': Path(r'C:\Users\amin\Projects\EMBER2024-benchmark-models\EMBER2024_exploit.model'),
    'packer': Path(r'C:\Users\amin\Projects\EMBER2024-benchmark-models\EMBER2024_packer.model'),
}

for name, p in models.items():
    data = p.read_bytes()
    print(f"=== {name} ===")
    print(f"  Size: {len(data)} bytes")
    print(f"  First 50 hex: {data[:50].hex()}")
    
    # Look for text markers
    for marker in [b'[Tree:', b'Tree=', b'tree\nversion=v4', b'tree\nversion=v']:
        idx = data.find(marker)
        if idx >= 0:
            # Show surrounding text
            end = min(idx + 300, len(data))
            text = data[idx:end].decode('ascii', errors='replace')
            print(f"  Found '{marker.decode()}' at offset {idx}:")
            print(f"    {text[:200]}")
            break
    else:
        # Check if it's a pickle
        if data.startswith(b'\x80'):
            print("  Format: pickle (binary)")
            # Find text inside
            for marker in [b'tree', b'Tree=']:
                idx = data.find(marker)
                if idx >= 0:
                    text = data[idx:idx+200].decode('ascii', errors='replace')
                    print(f"  Text inside pickle at {idx}: {text}")
        elif data[0:1] == b'\x00' or data[0:1] == b'\x01':
            print("  Format: raw binary")
        else:
            print(f"  First line: {data[:100]}")
    print()
