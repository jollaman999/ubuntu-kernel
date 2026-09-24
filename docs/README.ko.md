# jollaman999 ubuntu-kernel

Ubuntu 26.10 (stonking) 커널에 **arp_project** 를 얹은 트리다.

| | |
|---|---|
| 베이스 | Ubuntu `linux 7.3.0-6.6` (stonking-proposed), upstream `v7.3-rc4` |
| upstream stable | 아직 없다. `v7.3` 이 릴리즈되지 않았다 |
| 패키지 버전 | `7.3.0-13.13` → `uname -r` 은 `7.3.0-13-generic` |
| 이전 라인 | 7.2.x 작업은 `linux-7.2` 브랜치에 `7.2.3-11.11` 까지 남아 있다 |
| 추가 기능 | arp_project 2.5 |

## arp_project

기본 게이트웨이가 남의 하드웨어 주소로 넘어가는 것을 막는다. 게이트웨이
주소를 못박아 두고, 그것을 옮기려는 시도는 유니캐스트 ARP 프로브로 진짜
공격인지 정상 교체인지 가려낸 뒤에만 받아들인다.

노브는 `/sys/kernel/arp_project/` 에 있고 `how_to_use` 를 `cat` 하면
설명이 나온다. 한국어는 `how_to_use_ko` 다.

게이트웨이가 하드웨어 주소 하나로만 응답하지 않는 경우(HA 쌍, 본딩
링크)는 `allow_multi_gw_hwaddr` 로 다룬다. 기본값 `1` 이면 자기 앞으로
온 유니캐스트 프로브에 응답하는 두 번째 주소를 또 하나의 게이트웨이
포트로 받아들이고, `0` 이면 두 번째 응답을 공격으로 보고 차단한다.

자세한 문서:

- `Documentation/networking/arp_project.rst`
- `Documentation/translations/ko_KR/networking/arp_project.rst`

## 정품 우분투 커널과 다른 점

### zfs 를 여기서 빌드한다

우분투는 `linux-modules` 가 `linux-main-modules-zfs-<버전>` 을 `Depends`
로 요구하게 해 둔다. 우분투는 그 패키지를 별도 소스 패키지에서 자기 ABI 로
빌드하므로, 여기서 빌드한 커널에는 맞지 않는다. 그래서 이 트리가 그
패키지를 직접 빌드하고, 의존성은 우분투와 같게 둔다.

우분투가 이것을 `Recommends` 가 아니라 `Depends` 로 거는 데는 이유가
있다. 설치관리자가 root-on-ZFS 를 제공하고, 그런 시스템은 커널에
`zfs.ko` 가 없으면 부팅 자체가 안 된다.

- 소스는 `zfs-dkms_2.4.4-1ubuntu3_all.deb` 다. 빌드 중에 Launchpad 에서,
  안 되면 빌드 머신의 apt 저장소에서 받는다. 버전은
  `debian/rules.d/0-common-vars.mk` 의 `dkms_zfs_debpath` 가 정한다. zfs 를
  올리려면 거기를 고친다.
- 모듈은 `linux-main-modules-zfs-7.3.0-13-generic` 의
  `/usr/lib/modules/7.3.0-13-generic/kernel/zfs/zfs/` 에 들어간다.
- zfs 빌드가 실패하면 커널 빌드 전체가 멈춘다. zfs 없이 빌드하려면 아래 둘을
  같이 준다. 그래야 `linux-modules` 가 빌드되지 않은 패키지를 요구하지 않는다.

  ```sh
  env do_zfs=false do_linux_main_modules_depends=false ... fakeroot debian/rules binary-generic
  ```

### ccache 를 자동으로 쓴다

`ccache` 가 설치돼 있으면 `CC` 를 감싼다. `USE_CCACHE=0` 으로 끄고
`CCACHE=<경로>` 로 다른 바이너리를 지정한다. 없으면 아무것도 달라지지
않는다.

`HOSTCC` 는 감싸지 않는다. rustc 에 `-Clinker=$(HOSTCC)` 로 넘어가는데
rustc 가 첫 단어만 링커로 보기 때문이다.

## 빌드

우분투 26.10 이 아닌 곳에서 빌드하려면 컨테이너를 쓰는 편이 낫다.
gcc 15, rustc 1.97, clang 21, pahole 1.29 이상이 필요하다.

```sh
fakeroot debian/rules clean
env rustc=/usr/bin/rustc-1.97 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true DEB_BUILD_OPTIONS=parallel=$(nproc) \
    fakeroot debian/rules binary-generic
env rustc=/usr/bin/rustc-1.97 do_tools=false skipabi=true skipmodule=true \
    skipdbg=true skipretpoline=true \
    fakeroot debian/rules binary-indep
```

`rustc=` 를 지정하는 이유는 `debian.master/config/annotations` 가
`CONFIG_RUSTC_VERSION=109701` 을 요구하기 때문이다. 기본 `rustc` 가 그보다
낮으면 config 검사에서 멈춘다.

`binary-indep` 은 공용 헤더 패키지를 만든다. DKMS 가 그것을 필요로 한다.

## 설치

```sh
sudo dpkg -i linux-modules-7.3.0-13-generic_*.deb \
             linux-main-modules-zfs-7.3.0-13-generic_*.deb \
             linux-image-unsigned-7.3.0-13-generic_*.deb \
             linux-headers-7.3.0-13_*.deb \
             linux-headers-7.3.0-13-generic_*.deb
```

Secure Boot 를 켜 두었다면 `linux-image-unsigned` 는 부팅되지 않는다.

### Secure Boot

이 트리는 서명본을 만들지 않는다. 정품 우분투의 서명 커널
(`linux-image-7.3.0-13-generic`) 은 Canonical 의 서명 서비스에서 나오는
별도 소스(`linux-signed`)가 만드는 것이라 여기서 빌드한 커널로는 낼 수
없다. Secure Boot 를 켠 채로 쓰려면 둘 중 하나다.

- **직접 서명한다 (MOK).** 키를 한 번 만들어 펌웨어에 등록하고, 설치한
  커널 이미지에 서명한다. `mokutil`, `sbsigntool` 이 필요하다.

  ```sh
  openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key -out MOK.crt \
      -nodes -days 36500 -subj "/CN=local kernel/"
  openssl x509 -in MOK.crt -outform DER -out MOK.der

  sudo mokutil --import MOK.der   # 암호를 정한다. 재부팅하면 MOK 관리자가
                                  # 떠서 등록을 승인한다

  sudo sbsign --key MOK.key --cert MOK.crt \
      --output /boot/vmlinuz-7.3.0-13-generic /boot/vmlinuz-7.3.0-13-generic
  ```

  커널을 새로 설치할 때마다 그 이미지에 다시 서명해야 한다.

- **Secure Boot 를 끈다.** 펌웨어에서 끄면 unsigned 이미지가 그대로
  부팅된다.
