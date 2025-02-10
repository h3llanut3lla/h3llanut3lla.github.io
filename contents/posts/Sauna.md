---
title: "Sauna"
date: 2025-02-09
update: 2025-02-09
tags:
  - HTB
  - ASREPRoasting
  - PtH
  - DCSync
  - 윈도우즈
---
## Sauna 요약
![](https://velog.velcdn.com/images/h3llanut3lla/post/4a06e187-1d98-4268-9540-f1c4a459e2df/image.png)

> 🌟 **한 줄 평**
>
> 액티브 디렉토리의 기본적인 공격 요소 및 정보 수집 방법들을 경험할 수 있는 시스템인데, 잘 만들었다고 소문난 Pro Labs의 Dante를 만든 제작자 (egotisticalSW)가 만든 시스템이라 그런지 핵더박스내에서도 인기가 높다. 

사우나는 Active Directory 열거 및 활용 기능을 갖춘 쉬운 난이도의 윈도우즈 시스템이다. 

웹사이트에 나와 있는 직원 이름을 활용하여 사용자 이름 리스트를 만들어 ASREPRoasting 공격에 사용하면 컬브로스 사전 인증 (Kerberos pre-authentication)이 필요하지 않은 계정에 대한 해시를 얻을 수 있다. 이 해시를 이용하여 오프라인 무차별 대입 공격 (Offline brute force attack)을 수행 하게 되면 WinRM을 실행 할 수 있는 사용자 계정의 일반 텍스트 비밀번호를 얻을 수 있다. 

권한상승을 위한 정보 수집으로 WinPEAS를 실행하면 다른 시스템 사용자가 자동 로그인 설정을 해두었다는 사실과 비밀번호를 함께 확인 할 수 있다. 블러드하운드 (BloodHound)를 이용하면 이 사용자에게는 디씨씽크 (DCSync) 공격 시 도메인 컨트롤러에서 암호 해시를 덤프할 수 있는 `DS-Replication-Get-Changes-All` 확장 권한이 있다는 것을 알 수 있다. 이 공격을 실행하면 주 도메인 관리자의 해쉬를 얻을 수 있으며 이는 임패킷 (Impacket)의 피에스이그젝 (psexec.py)과 함께 사용함으로써 상승된 권한인 `NT_AUTHORITY\SYSTEM` 으로써 쉘을 열 수 있다. 

## 정보 수집
### Nmap 포트 스캔
```sh
PORT      STATE SERVICE                    
53/tcp    open  domain 
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds                          
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP              
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49681/tcp open  unknown
64471/tcp open  unknown
```
- 디렉토리 퍼징 (Directory Fuzzing) 에서는 딱히 눈에 띄는 폴더는 없었다. 
- LDAP을 열거하면 도메인명 `egotistical-bank.local` 을 확인 할 수 있다. 

### 80-HTTP
`http://egotistical-bank.local/about.html` 로 접속하면 직원들의 이름을 확인할 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/be597dbd-270e-439f-9379-9d46daf99b85/image.png)

### 유저네임 얻기
나중에 찾아보니 [Kerbrute](https://github.com/ropnop/kerbrute)를 활용해 좀 더 간결하고 스마트하게 사용자명을 얻는 방법이 있으나 나는 다른 방법으로 얻었다.

>Kerbrute를 활용하는 방법은 [이 문제풀이](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html#recon) 참조. 

[Username anarchy](https://github.com/urbanadventurer/username-anarchy)를 이용하여 직원들의 풀네임을 넣으면 그걸 치환해 유저네임 형식으로 바꿔주는데 다양한 형식의 유저네임 리스트를 ASREPRoasting 공격에 넣어 얻어 걸리길 기도하는 방법이다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/88c244c4-5d61-4be2-8646-8c54a7caf1cc/image.png)

## ASREPRoasting / 해시 얻기
### ASREPRoating 개념
구글링을 하다보면 글이 길고 설명이 복잡한것들이 대부분인데, [이 포스트](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html#as-rep-roasting)가 간결하고 쉽게 잘 설명한 것 같다. 

위 포스트를 요약하자면, 
- 사전 인증은 Kerberos 인증의 첫 번째 단계이며 주요 역할은 무차별 암호 추측 공격을 방지하는 것임. 
- 사전 인증 절차 중, 사용자는 타임스탬프를 암호화하는데 사용할 자격증명을 입력함. 
- DC는 이를 해독하여 올바른 자격 증명이 사용되었는지 확인함. 
- DC가 승인하면 TGT를 발행.
- 사전 인증이 비활성화되면 공격자가 _모든 _사용자에 대한 티켓을 요청할 수 있음.
- 따라서 명시적으로 계정에 `DONT_REQ_PREAUTH` (사전 인증 비활성화) 라는 설정이 있어야 가능한 공격임. 
- 그럼 DC는 오프라인에서 크랙할 수 있는 Kerberoast 공격과 유사하게 암호화된 TGT를 반환함. 

우선 컬브로스 88번 포트가 열려 있고, 윈도우즈 시스템이고, 사전인증이 비활성화된 계정이 있다면 시도해볼만 한 공격인 것 같다. 

### ASREPRoasting 시도
아래의 명령어를 입력해 위에서 만든 유저네임 리스트를 넣어 Impacket의 GetNPUsers를 사용해 ASREPRoasting 공격을 실행, 아웃풋으로 나온 해시를 `hash.txt` 파일에 저장한다. 

```sh
while read p; do impacket-GetNPUsers egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.10.10.175 >> hash.txt; done < unames.txt
```

그러면 아래와 같이 `fsmith` 사용자의 컬브로스 해쉬를 얻을 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/55f4b870-d498-48b7-969a-6d4cd964d98a/image.png)

일반 텍스트 비밀번호를 얻기 위해 해쉬캣을 이용해 무차별 대입을 하면 된다. 

```sh
hashcat -m 18200 fsmithhash /usr/share/wordlists/rockyou.txt --force
```

해쉬캣 모드는 `hashcat --help | grep Kerberos`를 입력해, `AS-REP` 이라고 적힌 모드 번호를 사용한다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/78b5413e-a491-483c-8936-f1744512efba/image.png)

그러면 이렇게 크랙된 비밀번호를 얻을 수 있다. 

- 유저네임: `fsmith`
- 비밀번호: `Thestrokes23`


## 초입
Evil-WinRM을 이용하여 새로 얻은 로그인 자격증명을 넣으면 초입에 성공할 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/43b2d8fa-fe29-411c-97df-7fd457d3aebf/image.png)

## 권한상승
### 정보 수집
[WinPEAS](https://github.com/peass-ng/PEASS-ng/blob/master/winPEAS/winPEASexe/README.md)를 실행하면 아래와 같이 자동로그인이 활성화된 계정정보를 비밀번호와 함께 얻을 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/7143ac67-0377-4a57-b206-1d392687d4c0/image.png)

- 유저네임: `svc_loanmanager`
- 비밀번호: `Moneymakestheworldgoround!`

### 시도 
초입 방식와 같이 새로 얻은 자격증명을 활용해 Evil WinRM을 통해 연결해보자. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/779305e0-89f4-430f-a9bf-9435496ee062/image.png)

## 블러드하운드 (BloodHound)
[블러드하운드](https://github.com/SpecterOps/BloodHound-Legacy)를 사용하면 액티브디렉토리 도메인 열거 및 시각화를 할 수 있는데 권한상승을 위한 정보 수집시 가이드 역할을 해주는 아주 유용한 툴이다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/ee48adf9-5457-41dc-af91-e94e39c5235f/image.png)

`Queries` 탭에서 `Find Principals with DCSync Rights` 를 클릭하면 현 사용자가 `GetChangesAll`을 통해 도메인과 연결이 된 것을 볼 수 있다.

가장자리를 우클릭하고 `Help`를 클릭하면 svc_loanmgr(현 사용자)가 DCSync 공격을 사용하여 도메인 컨트롤러에서 비밀번호 해시를 덤프할 수 있음을 알 수 있다.

![](https://velog.velcdn.com/images/h3llanut3lla/post/63046407-49dc-4d39-828d-1a0461df8a88/image.png)

## 디씨씽크 (DCSync)
![](https://velog.velcdn.com/images/h3llanut3lla/post/8682c72b-2a15-43ad-984b-c520fd415b15/image.png)

이렇게 하면 관리자의 해쉬를 얻을 수 있다. 
이 방법 외에도 미미켓즈 (Mimikatz)를 타겟에서 실행해 관리자 해쉬를 얻는 방법, 디씨씽크를 통해 얻은 해쉬를 Evil-WinRM에 그대로 넣어 관리자로써 연결하는 방법이 있다고 한다. 

## 패스더해시 (PtH)
나는 해쉬를 임패켓 (Impacket) 피에스이그젝 (psexec.py)에 넣어 패스하는 방법을 택했다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/bb50f669-d675-4dc1-b889-b7e982d0b215/image.png)
