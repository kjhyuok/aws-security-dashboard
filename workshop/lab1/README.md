# Lab 3: Amazon Q Developer CLI를 활용한 보안 점검 및 모니터링

## 개요
이 실습에서는 Amazon Q Developer CLI를 활용하여 개발된 AWS Security Dashboard를 통해 보안 위협을 탐지하고, Amazon Q Developer의 도움을 받아 해결하는 과정을 경험해보겠습니다. 이 대시보드는 100% Amazon Q Developer CLI를 활용하여 개발되었으며, AWS 계정 내의 보안 위협을 효과적으로 모니터링하고 대응할 수 있는 도구입니다.

## 실습 목표
- Amazon Q Developer CLI를 활용한 보안 대시보드 개발 방법 이해
- AWS 계정 내 보안 위협 요소 탐지 및 분석
- Amazon Q Developer를 통한 보안 위협 해결 방법 학습
- CLI 명령어를 활용한 효율적인 개발 방법 습득

## 사전 요구사항
- AWS 계정
- Amazon Q Developer CLI 설치
- Python 3.8 이상
- 필요한 Python 패키지 (requirements.txt 참조)

## 실습 단계

### 1단계: 환경 설정 및 대시보드 접속
1. Amazon Q Developer CLI 설치
   ```bash
   curl -s https://raw.githubusercontent.com/aws/aws-q-developer-cli/main/install.sh | bash
   source ~/.bashrc
   ```

2. 워크샵 저장소 클론
   ```bash
   git clone workshopstudio://ws-content-ea2f9c07-fa4c-4a78-b1c4-aa0426834e76/ai-powered-devsecops-with-amazon-q-developer-cli
   cd ai-powered-devsecops-with-amazon-q-developer-cli
   ```

3. 필요한 패키지 설치
   ```bash
   pip install -r requirements.txt
   ```

4. AWS 자격 증명 설정
   ```bash
   aws configure
   ```

5. 대시보드 실행
   ```bash
   streamlit run app.py
   ```

### 2단계: 보안 위협 탐지 및 분석
1. 대시보드 로그인 및 계정 인증
   - AWS 자격 증명을 사용하여 대시보드에 로그인
   - 실습용 계정 연결 확인

2. 보안 위협 스캔
   - S3 버킷 보안 설정 검사
   - WAF 규칙 및 설정 분석
   - GuardDuty 알림 확인
   - VPC Flow Logs 분석

3. 위협 등급 분류 확인
   - Low: 경미한 보안 위협
   - Medium: 중간 수준의 보안 위협
   - High: 심각한 보안 위협

### 3단계: Amazon Q Developer를 활용한 위협 해결
1. High 등급 위협 분석
   - 위협 상세 정보 확인
   - 영향도 및 잠재적 위험 평가

2. Amazon Q Developer CLI 활용
   ```bash
   q "AWS S3 버킷의 퍼블릭 액세스 차단 방법 알려줘"
   q "GuardDuty 알림에 대한 대응 방안 제시해줘"
   ```

3. 권장 조치 실행
   - Amazon Q Developer의 제안에 따른 보안 설정 변경
   - 변경 사항 검증 및 모니터링

## 추가 개발 가이드 (선택)
1. 대시보드 기능 확장
   - 새로운 보안 메트릭 추가
   - 커스텀 알림 설정
   - 보고서 생성 기능

2. Amazon Q Developer CLI 활용 팁
   - 효율적인 프롬프트 작성 방법
   - CLI 명령어 최적화
   - 자동화 스크립트 개발

## 실습 정리
1. 생성된 리소스 정리
   - 테스트용 S3 버킷 삭제
   - 임시 보안 그룹 제거
   - GuardDuty 설정 초기화

2. 학습 내용 정리
   - 보안 위협 탐지 방법
   - Amazon Q Developer CLI 활용 방법
   - 보안 대시보드 개발 경험

## 참고 자료
- [Amazon Q Developer CLI 공식 문서](https://docs.aws.amazon.com/q-developer-cli)
- [AWS 보안 모범 사례](https://aws.amazon.com/security)
- [Streamlit 공식 문서](https://docs.streamlit.io)

## 문제 해결
- CLI 설치 문제
- AWS 자격 증명 오류
- 대시보드 연결 실패
- 위협 스캔 오류

## 다음 단계
- 추가 보안 메트릭 구현
- 자동화된 대응 시스템 구축
- 커스텀 알림 설정
- 보고서 자동화
