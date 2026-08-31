# jollaman999 ubuntu-kernel

Ubuntu 26.10 (stonking) 커널에 **arp_project** 를 얹은 트리다.

| | |
|---|---|
| 베이스 | Ubuntu `linux 7.2.0-5.5` (stonking-proposed), upstream `v7.2` |
| upstream stable | `7.2.1`, `7.2.2` 를 커밋 단위로 반영 |
| 패키지 버전 | `7.2.2-5.5` → `uname -r` 은 `7.2.2-5-generic` |
| 추가 기능 | arp_project 2.4 |

## arp_project

기본 게이트웨이가 남의 하드웨어 주소로 넘어가는 것을 막는다. 게이트웨이
주소를 못박아 두고, 그것을 옮기려는 시도는 유니캐스트 ARP 프로브로 진짜
공격인지 정상 교체인지 가려낸 뒤에만 받아들인다.

노브는 `/sys/kernel/arp_project/` 에 있고 `how_to_use` 를 `cat` 하면
설명이 나온다. 한국어는 `how_to_use_ko` 다.

자세한 문서:

- `Documentation/networking/arp_project.rst`
- `Documentation/translations/ko_KR/networking/arp_project.rst`

## 정품 우분투 커널과 다른 점

### zfs 를 제공하지 않는다

우분투는 `linux-modules` 가 `linux-main-modules-zfs-<버전>` 을 `Depends`
로 요구하게 해 둔다. 그 패키지는 **별도 소스 패키지에서 우분투 ABI 로만**
만들어지므로, 여기서 빌드한 커널(`7.2.2-5`)용은 어디에도 없다.

의존성을 남겨두면 `dpkg` 가 `linux-modules` 설정을 거부하고, 그 상태가
남아 **apt 가 다른 패키지도 못 만지게 된다.** 그래서 뺐다.

우분투가 이것을 `Recommends` 가 아니라 `Depends` 로 거는 데는 이유가
있다. 설치관리자가 root-on-ZFS 를 제공하고, 그런 시스템은 커널에
`zfs.ko` 가 없으면 부팅 자체가 안 된다. 그래서 어떤 `linux-modules` 를
깔아도 zfs 루트가 뜨도록 보장해 둔 것이다.

이 소스 패키지로는 그것을 만들 수 없다. `linux-main-modules-zfs` 는
서명본 소스(`linux-main-signed`)에서 나오고, 이 트리의
`all_dkms_modules` 는 비어 있으며 zfs 소스도 들어 있지 않다.

**zfs 가 필요하면 `zfs-dkms` 를 쓴다.** 헤더가 있는 커널이면 어디에나
빌드된다.

```sh
sudo apt install zfs-dkms linux-headers-7.2.2-5-generic
dkms status | grep zfs
```

**루트가 zfs 라면 이 커널로 재부팅하기 전에 위를 먼저 하고
`dkms status` 로 확인한다.** 확인 없이 재부팅하면 부팅되지 않는다.

### ccache 를 자동으로 쓴다

`ccache` 가 설치돼 있으면 `CC` 를 감싼다. `USE_CCACHE=0` 으로 끄고
`CCACHE=<경로>` 로 다른 바이너리를 지정한다. 없으면 아무것도 달라지지
않는다.

`HOSTCC` 는 감싸지 않는다. rustc 에 `-Clinker=$(HOSTCC)` 로 넘어가는데
rustc 가 첫 단어만 링커로 보기 때문이다.

## 빌드

우분투 26.10 이 아닌 곳에서 빌드하려면 컨테이너를 쓰는 편이 낫다.
gcc 15, rustc 1.95, clang 21, pahole 1.29 이상이 필요하다.

```sh
fakeroot debian/rules clean
env rustc=/usr/bin/rustc-1.95 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true DEB_BUILD_OPTIONS=parallel=$(nproc) \
    fakeroot debian/rules binary-generic
env rustc=/usr/bin/rustc-1.95 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true \
    fakeroot debian/rules binary-indep
```

`rustc=` 를 지정하는 이유는 `debian.master/config/annotations` 가
`CONFIG_RUSTC_VERSION=109500` 을 요구하기 때문이다. 기본 `rustc` 가 그보다
낮으면 config 검사에서 멈춘다.

`binary-indep` 은 공용 헤더 패키지를 만든다. DKMS 가 그것을 필요로 한다.

## 설치

```sh
sudo dpkg -i linux-modules-7.2.2-5-generic_*.deb \
             linux-image-unsigned-7.2.2-5-generic_*.deb \
             linux-headers-7.2.2-5_*.deb \
             linux-headers-7.2.2-5-generic_*.deb
```

Secure Boot 를 켜 두었다면 `linux-image-unsigned` 는 부팅되지 않는다.
