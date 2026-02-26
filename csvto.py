input_files = ["1.csv", "2.csv", "3.csv"]
addresses = set()

for file in input_files:
    with open(file, "r", encoding="utf-8") as f:
        next(f)  # skip header
        
        for line in f:
            parts = line.strip().split("\t")
            if parts:
                addresses.add(parts[0])

with open("output_address.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(sorted(addresses)))

print("✅ Done:", len(addresses))
