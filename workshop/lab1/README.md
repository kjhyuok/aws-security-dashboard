# Lab 1: AWS Security Dashboard 인프라 구축

## 개요
이 실습에서는 AWS Security Dashboard를 위한 인프라를 CloudFormation을 사용하여 구축합니다. 
구축되는 인프라에는 AWS WAF, GuardDuty, VPC Flow Logs가 포함되어 있으며, 
이러한 서비스들이 수집하는 보안 데이터를 대시보드에서 시각화할 수 있는 기반을 마련합니다.

## 사전 요구사항
- AWS 계정
- AWS CLI 설치 및 구성
- CloudFormation 템플릿 실행 권한
- EC2 키 페어 (SSH 접속용)

## 실습 단계

### 1. CloudFormation 스택 생성
1. AWS Management Console에 로그인합니다.
2. CloudFormation 서비스로 이동합니다.
3. "스택 생성" > "새 리소스 사용(표준)"을 선택합니다.
4. `security-dashboard-infra.yaml` 템플릿을 업로드합니다.
5. 스택 이름을 입력하고 다음을 클릭합니다.
6. 파라미터를 검토하고 필요한 경우 수정합니다:
   - Environment: dev 또는 prod
   - VpcId: 기본 VPC ID
   - KeyName: EC2 인스턴스 접속에 사용할 키 페어 이름
   - WorkshopIP: 워크샵 참가자의 IP 주소 범위 (CIDR 표기법)
7. 스택을 생성합니다.

### 2. 생성된 리소스 확인
CloudFormation 스택이 생성되면 다음 리소스들이 자동으로 구성됩니다:

- **EC2 인스턴스**
  - Amazon Linux 2023 AMI
  - t2.micro 인스턴스 유형
  - 보안 그룹 (SSH 및 Streamlit 포트)
  - IAM 역할 및 정책

- **VPC Flow Logs**
  - CloudWatch Logs 그룹
  - IAM 역할 및 정책

- **GuardDuty**
  - GuardDuty 감지기
  - 기본 보안 설정

- **WAF**
  - Web ACL
  - AWS 관리형 규칙 세트
  - OWASP 규칙 세트

- **Security Dashboard**
  - S3 버킷
  - Lambda 함수
  - API Gateway
  - IAM 역할 및 정책

### 3. 출력값 확인
스택 생성이 완료되면 다음 출력값들을 확인할 수 있습니다:

- WorkshopInstancePublicIP: 워크샵 EC2 인스턴스의 공용 IP 주소
- WorkshopInstancePublicDNS: 워크샵 EC2 인스턴스의 공용 DNS 이름
- SecurityDashboardAPIEndpoint: API Gateway 엔드포인트 URL
- SecurityDashboardBucketName: S3 버킷 이름
- GuardDutyDetectorId: GuardDuty 감지기 ID
- WAFWebACLId: WAF Web ACL ID

### 4. EC2 인스턴스 접속
1. SSH를 사용하여 EC2 인스턴스에 접속합니다:
```bash
ssh -i <your-key.pem> ec2-user@<WorkshopInstancePublicIP>
```

2. 필요한 패키지가 자동으로 설치되었는지 확인합니다:
```bash
python3 --version
pip3 list
```

## 다음 단계
Lab 2에서는 이 인프라를 기반으로 Security Dashboard 애플리케이션을 개발하고, 
수집된 보안 데이터를 시각화하는 방법을 실습합니다.

## 문제 해결
- CloudFormation 스택 생성 실패 시 CloudFormation 콘솔에서 이벤트 로그를 확인합니다.
- IAM 권한 문제가 발생한 경우 사용 중인 IAM 사용자/역할의 권한을 확인합니다.
- 리소스 생성 실패 시 AWS 서비스 할당량을 확인합니다.
- EC2 인스턴스 접속 실패 시:
  - 키 페어가 올바르게 생성되었는지 확인
  - 보안 그룹에서 SSH 포트(22)가 열려있는지 확인
  - 인스턴스의 상태 확인 