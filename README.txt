import sys

def parse_hostnames(file_path):
    unique_hosts = set()

    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) == 3 and ("true" in parts[1:] or "True" in parts[1:]):
                unique_hosts.add(parts[0])

    for host in sorted(unique_hosts):
        print(host)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file>")
        sys.exit(1)

    parse_hostnames(sys.argv[1])
