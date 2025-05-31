## 1단계: Dashboard 접속과 CLI를 통한 개발과정 분석

### 실습 목표
- AWS Security Dashboard의 주요 기능과 구조 이해하기
- Amazon Q Developer CLI를 활용한 개발 프로세스 파악하기
- 실습용 AWS 계정의 보안 상태 분석하기

### 준비 사항
- AWS 계정 접근 정보 (IAM 자격 증명)
- Amazon Q Developer CLI
- 웹 브라우저 (Chrome 권장)
- 터미널 접근 권한

### 실습 과정

#### 1. AWS Security Dashboard 접속 및 초기 설정

1. 제공된 EC2 인스턴스 URL로 접속:
   ```
   http://[EC2-PUBLIC-IP]:8501
   ```

2. AWS 자격 증명으로 로그인:
   - AWS 계정 ID 입력
   - Access Key ID 입력
   - Secret Access Key 입력
   - 리전 선택 (ap-northeast-2)

3. 계정 검증:
   - "계정 검증" 버튼 클릭
   - 성공 메시지 확인

#### 2. 대시보드 기능 탐색

1. 메인 대시보드 구성 확인:
   - IAM 계정 현황
   - CloudTrail 로그
   - 보안 이슈 발견
   - 권장 조치

2. 각 탭의 주요 기능 살펴보기:
   - **IAM 계정 현황**: 사용자, 역할, 그룹 정보
   - **CloudTrail 로그**: API 호출 이력
   - **발견 사항**: S3, WAF, GuardDuty 보안 이슈
   - **권장 조치**: Amazon Q 기반 해결 방안

#### 3. Amazon Q Developer CLI 분석

1. CLI 환경 설정:
   ```bash
   # Amazon Q CLI 버전 확인
   q --version
   
   # 개발 모드 진입
   q dev
   ```

2. 개발 과정 분석을 위한 프롬프트 예시:
   ```
   # 대시보드 구조 분석
   q "AWS Security Dashboard의 주요 컴포넌트와 데이터 흐름을 설명해줘"
   
   # 보안 검사 로직 분석
   q "S3 버킷 보안 설정을 확인하는 코드를 작성해줘"
   
   # 시각화 구현 분석
   q "Streamlit에서 보안 메트릭을 시각화하는 방법을 알려줘"
   ```

3. 소스 코드 분석:
   ```bash
   # 주요 파일 구조 확인
   ls -R /Users/kjhyuok/Documents/AWS_Todo/000_project_github/vscode/workshop/lab1/
   
   # app.py 내용 확인
   cat /Users/kjhyuok/Documents/AWS_Todo/000_project_github/vscode/workshop/lab1/app.py
   ```

#### 4. 보안 스캔 및 분석

1. 보안 스캔 실행:
   - "보안 스캔 시작" 버튼 클릭
   - 스캔 진행 상태 모니터링
   - 결과 대기

2. 스캔 결과 분석:
   - 발견된 보안 이슈 목록 확인
   - 심각도별 분류 (Low, Medium, High)
   - 영향받는 리소스 식별

3. Amazon Q를 활용한 해결 방안 탐색:
   ```
   q "발견된 [이슈 유형] 보안 위협에 대한 해결 방법을 알려줘"
   ```

### 실습 결과 정리

1. 발견된 주요 보안 이슈:
   - 이슈 1: [이슈 설명]
   - 이슈 2: [이슈 설명]
   - 이슈 3: [이슈 설명]

2. Amazon Q 활용 경험:
   - 개발 과정 분석
   - 코드 생성 및 수정
   - 문제 해결 방안 도출

3. 다음 단계 준비:
   - 발견된 보안 이슈 우선순위 설정
   - 해결 방안 구체화
   - 추가 분석이 필요한 영역 파악

### 참고 사항
- AWS Security Dashboard는 Streamlit 기반으로 구현
- Amazon Q Developer CLI는 개발 과정 전반에 활용
- 보안 스캔 결과는 실시간으로 업데이트
- 모든 보안 이슈는 심각도에 따라 분류됨
