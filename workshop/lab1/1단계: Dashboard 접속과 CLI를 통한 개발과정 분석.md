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
<img width="1117" alt="image" src="https://github.com/user-attachments/assets/1bd521ff-dd0b-4ff3-810e-c108796427c1" />

2. AWS 자격 증명으로 로그후 계정을 검증해 봅니다.
   - 인스턴스 프로파일 사용에 check!
   - 리전 선택 (us-east-1)
<img width="1375" alt="image" src="https://github.com/user-attachments/assets/a3d12d93-2e8b-4c4d-97f1-be8bad0286b1" />
<img width="1374" alt="image" src="https://github.com/user-attachments/assets/2f5b673b-0875-4f9c-a7aa-497a6aef72ff" />

#### 2. 대시보드 기능 탐색

1. 메인 대시보드 구성을 확인해 봅니다. 아래의 각 Tab에서는 아래와 같은 정보를 확인할 수 있고 각 용도는 다음과 같습니다.
   - **IAM 계정 현황**: 사용자, 역할, 그룹 정보
   - **CloudTrail 로그**: API 호출 이력
   - **발견 사항**: S3, WAF, GuardDuty 보안 이슈
   - **권장 조치**: Amazon Q 기반 해결 방안 가이드
<img width="1365" alt="image" src="https://github.com/user-attachments/assets/8025aab1-c870-4f31-a198-4d0bcc3a8f5a" />

#### 3. 보안 스캔 및 분석

1. **프로파일 검증** 을 눌러서 **AWS 계정 정보를 성공적으로 가져왔습니다** 라는 메시지 확인 후 **보안스캔 시작** 버튼을 클릭하면 현재 실습중인 AWS Account의 IAM 리소스정보, CloudTrail Log정보를 자동으로 조회합니다.
   - 실제 정보를 가져오는지 각 Tab에서 확인해 봅니다.
<img width="1367" alt="image" src="https://github.com/user-attachments/assets/0bc4019a-0cd4-4ac4-b428-ddc0d21b25fb" />

또한 "발견사항Tab" 에는 자동으로 Account를 스캔하여 조회된 S3 버킷 보안 설정, WAF 규칙, GuardDuty 알림에 대해 Low, Medium, High 심각도 등급으로 분류된 결과가 카드형식으로 표현됩니다.
<img width="1353" alt="image" src="https://github.com/user-attachments/assets/06a67c29-8ac4-4960-960c-f1c1d62e0d2a" />

#### 4. Amazon Q Developer CLI를 통한 AWS Security Dashboard 개발과정 TIP!

1. Frontpage를 시작으로 구현하려는 애플리케이션의 개발 목적과 기능을 주입하기 
   - 구체적인 Prompt를 통해서 Application 개발명세를 Q CLI를 통해서 작성해 봅니다.
   - 대시보드의 목적, 개발언어, 필요한 기능동작에 대해 Front Page를 먼저 작업할 수 있도록 지시 합니다.
   - Front page가 만족스러울 때까지 결과를 확인하며 디테일하게 가이드를 내려주고 필요에 따라 디자인 개선도 요청해 봅니다.
<img width="985" alt="image" src="https://github.com/user-attachments/assets/cd03545c-026a-4e19-b4b3-d6f33de3837d" />
<img width="1261" alt="image" src="https://github.com/user-attachments/assets/f11a838c-30c8-49bc-9c5e-65980be10be7" />

2. 완성된 Frontpage에 구현된 각 버튼 그리고 연동되는 계정에 대한 설정등을 요청하기
   - 각 버튼을 눌렀을때의 동작을 구체적으로 가이드 해줍니다.
   - AWS와의 연동이 필요한 시점에는 Role, Accesskey 등 기반으로 부탁하거나 또 다른 안정적인 수단이 없는지 확인하고 가이드 받습니다.
<img width="940" alt="image" src="https://github.com/user-attachments/assets/136a2742-ccb6-4936-aba6-2d1a16fd6df6" />
<img width="1047" alt="image" src="https://github.com/user-attachments/assets/40b2864a-9039-42ac-a023-5b9a766984f4" />

3. 트러블 슈팅
   - 개발과정중 발생하는 Page의 에러나 메시지에 대해서는 실시간으로 Amazon Q Developer CLI 에게 질문하여 개선합니다.
   - Amazon Q Developer CLI 와 개발중에는 현재 수행하는 프로젝트의 절대경로를 포함하여 질문해보고 분석을 주기적으로 요청하며, 개발의 의도를 주입할 수 있도록 재확인 하면 결과물이 더 좋습니다.
<img width="1190" alt="image" src="https://github.com/user-attachments/assets/6e8c21e7-2503-4241-bfcb-b774a0b1bd3b" />

### 참고 사항
- AWS Security Dashboard는 Streamlit 기반으로 구현
- Amazon Q Developer CLI는 개발 과정 전반에 활용
- 보안 스캔 결과는 실시간으로 업데이트
- 모든 보안 이슈는 심각도에 따라 분류됨
