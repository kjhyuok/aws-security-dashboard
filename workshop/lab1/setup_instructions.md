# AWS 보안 대시보드 워크숍 설정 가이드

이 가이드는 AWS 보안 대시보드 워크숍을 위한 환경 설정 방법을 안내합니다.

## 사전 준비 사항

1. AWS 계정
2. AWS CLI가 설치된 환경
3. 관리자 권한이 있는 IAM 사용자 또는 역할

## CloudFormation 스택 배포

1. 다음 명령어를 사용하여 CloudFormation 스택을 배포합니다:

```bash
aws cloudformation create-stack \
  --stack-name security-dashboard \
  --template-body file://security-dashboard-infra.yaml \
  --parameters \
    ParameterKey=VpcId,ParameterValue=vpc-xxxxxxxx \
    ParameterKey=SubnetId,ParameterValue=subnet-xxxxxxxx \
    ParameterKey=Environment,ParameterValue=dev \
    ParameterKey=WorkshopIP,ParameterValue=0.0.0.0/0 \
  --capabilities CAPABILITY_IAM
```

2. VpcId와 SubnetId는 실제 사용할 VPC와 서브넷 ID로 변경하세요.

## 스택 배포 확인

1. AWS Management Console에서 CloudFormation 서비스로 이동합니다.
2. 'security-dashboard' 스택이 CREATE_COMPLETE 상태가 될 때까지 기다립니다.
3. 스택의 '출력' 탭에서 'DashboardURL' 값을 확인합니다.

## 대시보드 접속

1. 브라우저에서 'DashboardURL' 값으로 접속합니다.
2. 대시보드가 정상적으로 로드되면 왼쪽 사이드바에서 'Amazon Q 보안 조치' 페이지를 선택합니다.
3. '보안 위협 시뮬레이션 실행' 버튼을 클릭하여 보안 위협을 시뮬레이션합니다.
4. 1-2분 후 '보안 이벤트 새로고침' 버튼을 클릭하여 생성된 보안 이벤트를 확인합니다.

## Amazon Q Developer 활용

1. 보안 이벤트를 선택하여 상세 정보를 확인합니다.
2. 'Amazon Q에게 물어보기' 섹션에서 보안 이벤트에 대한 질문을 입력합니다.
3. AWS Management Console에서 Amazon Q Developer를 활용하여 보안 이벤트를 분석하고 해결 방법을 찾습니다.

## 정리

워크숍 완료 후 다음 명령어로 리소스를 정리합니다:

```bash
aws cloudformation delete-stack --stack-name security-dashboard
```

## 문제 해결

- EC2 인스턴스 연결 문제: EC2 콘솔에서 인스턴스를 선택하고 '연결' 버튼을 클릭하여 EC2 Instance Connect를 통해 연결할 수 있습니다.
- 대시보드 로드 문제: EC2 인스턴스에 SSH로 접속하여 `/var/log/user-data.log` 파일을 확인하세요.
- 보안 위협 시뮬레이션 문제: CloudWatch Logs에서 Lambda 함수의 로그를 확인하세요.
