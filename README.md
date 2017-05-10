# Multi User Blog

# 운동 기록 일지 프로젝트. 
파이썬 템플릿 라이브러리 Jinja2와 구글 앱 엔진을 사용하여 만든 블로그입니다. 여러 사용자가 가입하여 글을 쓸 수 있습니다. 글을 쓰면 쓴 사람의 위치가 구글 맵에 표시됩니다. 메인 화면에는 모든 글과 모든 글쓴이 위치가 표시됩니다.
각 페이지의 맨 아래에는 구글 앱 엔진의 맴캐시를 사용하여 쿼리를 몇 초전에 요청했는지를 보여줍니다. 


## 시작하기
깃허브 주소를 복사해서 로컬 드라이브에 복사한 후 구글 앱 엔진을 통해 로컬에서 실행할 수 있습니다. 자세한 내용은 다음을 참조하세요.(https://cloud.google.com/appengine/docs/standard/python/quickstart)

또는 간단하게 다음 사이트에 접속하세요.

http://mymangoblog.appspot.com/blog


## 사용한 스택 및 언어:
* [Google App Engine]
* [Jinja2]
* [Python]
* [Bootstrap]

   [Google App Engine]: <https://cloud.google.com/appengine/docs/>
   [Jinja2]: <http://jinja.pocoo.org/docs/2.9/>
   [Python]: <https://www.python.org/>
   [bootstrap]: <http://getbootstrap.com/>


## 지시사항:


### 로컬에서 실행하기

1. 먼저 구글 클라우드 SDK를 설치합니다.

https://cloud.google.com/appengine/docs/standard/python/download

2. 깃허브 저장소를 로컬 머신에 저장합니다. (이를 위해서 git cli가 필요합니다.)

git clone https://github.com/GoogleCloudPlatform/python-docs-samples

3. 해당 폴더로 이동하여 다음을 입력합니다.

`dev_appserver.py ./`

