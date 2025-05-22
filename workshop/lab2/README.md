# Lab 2: AWS Security Dashboard 개발

## 개요
이 실습에서는 Lab 1에서 구축한 인프라를 기반으로 Security Dashboard 애플리케이션을 개발하고 배포합니다.
대시보드는 AWS WAF, GuardDuty, VPC Flow Logs에서 수집된 보안 데이터를 시각화하고,
보안 이벤트를 실시간으로 모니터링할 수 있는 기능을 제공합니다.

## 사전 요구사항
- Lab 1 완료
- AWS 계정
- AWS CLI 설치 및 구성

## 실습 단계

### 1. EC2 인스턴스 설정
1. AWS Management Console에서 EC2 서비스로 이동합니다.
2. "인스턴스 시작"을 클릭합니다.
3. 다음 설정으로 인스턴스를 구성합니다:
   - 이름: `security-dashboard-workshop`
   - AMI: Amazon Linux 2023
   - 인스턴스 유형: t2.micro
   - 키 페어: 새로 생성 또는 기존 키 페어 선택
   - 네트워크 설정: 기본 VPC 사용
   - 보안 그룹: 다음 인바운드 규칙 추가
     - SSH (포트 22): 내 IP
     - Custom TCP (포트 8501): 내 IP (Streamlit 접속용)
4. "인스턴스 시작"을 클릭합니다.

### 2. EC2 인스턴스 접속 및 환경 설정
1. SSH를 사용하여 EC2 인스턴스에 접속합니다:
```bash
ssh -i <your-key.pem> ec2-user@<your-instance-public-ip>
```

2. 시스템 패키지를 업데이트하고 필요한 도구를 설치합니다:
```bash
sudo yum update -y
sudo yum install -y git python3-pip
```

3. Python 가상 환경을 설정합니다:
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. 프로젝트 설정
1. 프로젝트 디렉토리를 생성하고 필요한 파일들을 다운로드합니다:
```bash
mkdir aws-security-dashboard
cd aws-security-dashboard
git clone https://github.com/kjhyuok/aws-security-dashboard.git .
```

2. 필요한 Python 패키지를 설치합니다:
```bash
pip install -r requirements.txt
```

### 4. AWS 자격 증명 설정
1. AWS CLI를 사용하여 자격 증명을 설정합니다:
```bash
aws configure
```
- AWS Access Key ID 입력
- AWS Secret Access Key 입력
- Default region name: ap-northeast-2
- Default output format: json

### 5. 대시보드 실행
1. Streamlit 앱을 백그라운드에서 실행합니다:
```bash
nohup streamlit run app.py --server.port 8501 --server.address 0.0.0.0 &
```

2. 웹 브라우저에서 다음 URL로 접속하여 대시보드를 확인합니다:
```
http://<your-instance-public-ip>:8501
```

### 6. 기능 테스트
1. WAF 메트릭 확인
   - 요청 수
   - 차단된 요청 수
   - 규칙별 트래픽

2. GuardDuty 알림 확인
   - 보안 이벤트 목록
   - 심각도별 분류
   - 이벤트 상세 정보

3. VPC Flow Logs 분석
   - 트래픽 패턴
   - IP 주소별 통계
   - 프로토콜별 분석

## 문제 해결
- EC2 인스턴스 접속 실패: 보안 그룹 설정을 확인합니다.
- Streamlit 접속 실패: 
  - 보안 그룹에서 포트 8501이 열려있는지 확인
  - Streamlit이 올바른 주소와 포트로 실행되었는지 확인
- AWS 자격 증명 오류: AWS CLI 설정을 확인합니다.
- 데이터 로딩 실패: IAM 권한을 확인합니다.
- 메모리 부족: 데이터 처리 방식을 최적화합니다.
- 성능 이슈: 캐싱을 구현하고 쿼리를 최적화합니다.

## 정리
1. EC2 인스턴스 종료:
   - AWS Management Console에서 인스턴스를 선택하고 "인스턴스 상태" > "인스턴스 종료"를 클릭합니다.
2. 생성된 키 페어 삭제 (선택사항):
   - EC2 콘솔의 "키 페어" 섹션에서 사용한 키 페어를 삭제합니다.

## 다음 단계
- 대시보드 기능 확장
- 알림 설정 추가
- 사용자 인증 구현
- 데이터 백업 및 보관 정책 수립 