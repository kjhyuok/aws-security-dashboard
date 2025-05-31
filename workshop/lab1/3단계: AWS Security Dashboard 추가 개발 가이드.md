# 3단계: AWS Security Dashboard 추가 개발 가이드 (선택)

## 실습 목표
• Amazon Q Developer CLI를 활용한 대시보드 기능 확장
• 보안 메트릭, 알림, 보고서 기능 추가 개발
• Streamlit 기반 대시보드 커스터마이징
• 실제 보안 운영에 활용 가능한 기능 구현

## 준비 사항
• 1, 2단계 실습 완료
• Python 및 Streamlit 기본 지식
• AWS SDK for Python (Boto3) 사용 경험
• 코드 편집기 (VS Code 등)

## 실습 과정

### 1. 개발 환경 설정

1. 프로젝트 코드를 로컬 환경에 복제합니다:
bash
git clone <repository-url>
cd <project-directory>


2. 가상 환경을 생성하고 필요한 패키지를 설치합니다:
bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 또는
.\venv\Scripts\activate  # Windows

pip install -r requirements.txt


3. 기존 대시보드 코드를 살펴봅니다:
bash
cat /Users/kjhyuok/Documents/AWS_Todo/000_project_github/vscode/workshop/lab1/app.py


### 2. 새로운 보안 메트릭 추가

1. Amazon Q Developer CLI를 활용하여 추가할 보안 메트릭에 대한 아이디어를 얻습니다:
bash
q "AWS 환경에서 모니터링해야 할 중요한 보안 메트릭은 무엇이 있을까?"
q "Streamlit에서 시계열 보안 데이터를 시각화하는 코드를 작성해줘"


2. 다음 중 하나 이상의 메트릭을 구현해 봅니다:
   • **리소스 노출 지수**: 퍼블릭 액세스 가능한 리소스의 비율
   • **패치 상태 모니터링**: EC2 인스턴스의 패치 적용 상태
   • **권한 복잡성 지수**: IAM 정책의 복잡성 및 과도한 권한 분석
   • **암호화 준수율**: 암호화 설정이 적용된 리소스의 비율

3. 선택한 메트릭을 위한 데이터 수집 함수를 작성합니다:
python
def collect_encryption_compliance_data():
    # 암호화 준수율 데이터 수집 로직
    # Amazon Q Developer CLI로 생성된 코드 활용
    pass


4. Streamlit 대시보드에 시각화 요소를 추가합니다:
python
def render_encryption_compliance_chart(data):
    # 암호화 준수율 차트 렌더링 로직
    # Amazon Q Developer CLI로 생성된 코드 활용
    pass


### 3. 커스텀 알림 설정 기능 구현

1. Amazon Q Developer CLI를 활용하여 알림 시스템 구현 방법을 조회합니다:
bash
q "Streamlit에서 사용자 지정 알림 설정 기능을 구현하는 방법은?"
q "AWS SNS를 사용하여 보안 알림을 전송하는 Python 코드를 작성해줘"


2. 알림 설정 UI를 구현합니다:
   • 알림 유형 선택 (이메일, SMS, Slack 등)
   • 알림 트리거 조건 설정
   • 알림 메시지 템플릿 커스터마이징

3. AWS SNS 또는 다른 알림 서비스와 연동하는 코드를 작성합니다:
python
def setup_security_alerts(alert_config):
    # 알림 설정 로직
    # Amazon Q Developer CLI로 생성된 코드 활용
    pass


### 4. 보고서 생성 기능 개발

1. Amazon Q Developer CLI를 활용하여 보고서 생성 기능 구현 방법을 조회합니다:
bash
q "Python으로 보안 보고서를 PDF로 생성하는 방법은?"
q "Streamlit에서 데이터를 CSV로 내보내는 기능을 구현하는 코드를 작성해줘"


2. 다음 형식의 보고서 생성 기능을 구현합니다:
   • PDF 보고서: 경영진용 요약 보고서
   • CSV 내보내기: 상세 보안 분석 데이터
   • 이메일 전송: 정기 보안 보고서 자동 전송

3. 보고서 템플릿과 생성 로직을 구현합니다:
python
def generate_security_report(report_type, data):
    # 보고서 생성 로직
    # Amazon Q Developer CLI로 생성된 코드 활용
    pass


### 5. 기타 창의적인 기능 구현

Amazon Q Developer CLI를 활용하여 다음과 같은 추가 기능을 자유롭게 구현해 봅니다:

1. 보안 점수 시스템: 다양한 보안 지표를 종합한 점수 체계 구현
bash
q "AWS 리소스의 보안 점수를 계산하는 알고리즘을 Python으로 구현해줘"


2. 비용 최적화 제안: 보안을 유지하면서 비용을 절감할 수 있는 방안 제시
bash
q "AWS 보안 서비스의 비용 최적화 방안을 분석하는 코드를 작성해줘"


3. 머신러닝 기반 이상 탐지: CloudTrail 로그 분석을 통한 이상 행동 탐지
bash
q "Python으로 CloudTrail 로그에서 이상 행동을 탐지하는 간단한 ML 모델을 구현해줘"


### 6. 테스트 및 발표 준비

1. 구현한 기능을 테스트하고 버그를 수정합니다.

2. 다음 내용을 포함한 간단한 발표 자료를 준비합니다:
   • 구현한 기능 소개
   • 기술적 접근 방식 설명
   • 실제 보안 운영에서의 활용 방안
   • Amazon Q Developer CLI의 활용 사례

3. 팀원들에게 구현한 기능을 시연하고 피드백을 수집합니다.

## 마무리

1. 개발한 코드를 GitHub 저장소에 커밋합니다.

2. 추가 개선 사항 및 향후 개발 방향을 정리합니다.

3. 워크숍 전체 과정에 대한 회고를 진행합니다:
   • AWS Security Dashboard의 유용성
   • Amazon Q Developer CLI의 개발 생산성 향상 효과
   • 실제 업무에 적용할 수 있는 아이디어
