# FINAL FANTASY XIV - Scraper Chat v0.1
> 파이널판타지14 글로벌 한국어 채팅 프로그램 입니다.
<br/>

![Imgur](http://i.imgur.com/mpDM9TW.png)
![Imgur](http://i.imgur.com/9KZky4h.jpg)

## 기능정의:

 * FC 한글채팅 교환이 가능.
 * Party 한글채팅 교환이 가능.
 * Party or FC 상대방이 입력한 일본어는 한국어로 번역되어 출력됩니다. (자신은 제외)
 * 번역은 구글 클라우드 번역 API를 사용하며, 1일 200만 문자열 제한입니다.
 * 테스트를 위해 API 키도 제공하지만, API키를 이용해 무분별하게 사용되는게 확인이 되면 차단합니다.
 

## 알려진 버그:

 * 장시간 실행 중일때 프로그램이 뻗는 버그가 있음. (외부 솔루션 이슈)
 * 불필요한 패킷이 입력되는 문제가 있는데, 최대한 잡아내고 있습니다.
 * 현재 개행이 안되는데, 기능을 곧 추가 예정입니다.

<br/>

## 설치

1. [WinPacp 다운로드(필수)](https://www.winpcap.org/install/default.htm)
2. [Scraper Chat 다운로드](https://github.com/kimyearho/FF14_ScraperChat/releases/tag/v0.1.1)
3. 압축해제 후 scraper.exe로 설치하고, jnetpcap.dll을 c:\Windows/System32 위치로 복사

<br/>

## 주의사항

네트워크 환경 어댑터 설정에 사용하는 어댑터외에는 비활성화 해주세요.
![Imgur](http://i.imgur.com/wUe12OZ.png)

<br/>

# 저작권
```javascript
기재되어있는 회사명 · 제품명 · 시스템 이름은 해당 소유자의 상표 또는 등록 상표입니다.

(C) 2010 - 2017 SQUARE ENIX CO., LTD All Rights Reserved.
