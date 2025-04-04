# 🕵️‍♂️ TCP Packet Sniffer - WhiteHat School 3기 과제

이 프로젝트는 **화이트햇 스쿨 3기 - 네트워크 기초** 과정에서 진행한 과제로,  
`libpcap` 라이브러리를 활용하여 **TCP 패킷을 실시간으로 캡처하고 분석**하는 프로그램입니다.

<br>

## 📌 주요 기능

- 네트워크 장치에서 실시간으로 패킷 캡처
- Ethernet, IP, TCP 헤더 정보 출력
- TCP 페이로드 일부(최대 16바이트) 출력
- TCP 프로토콜만 필터링하여 캡처

<br>

## 💻 사용 기술

- C 언어
- libpcap
- Linux 기반 개발 환경 (Ubuntu 등)
- gcc 컴파일러

<br>

## ⚙️ 실행 방법

1. **libpcap 설치**
   ```bash
   sudo apt update
   sudo apt install libpcap-dev
   gcc packet_sniffer.c -lpcap -o packet_sniffer
   ip link show     # 인터페이스 이름 확인 (특정 장치로 지정해야합니다. Wlp3s0처럼..)
   ./packet_sniffer

