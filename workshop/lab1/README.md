# Lab 3: AWS Account 보안위협 탐지 및 Q CLI를 활용한 조치

## 개요
이 실습에서는 Amazon Q Developer CLI를 활용하여 개발된 AWS Security Dashboard를 통해 보안 위협을 탐지하고, Amazon Q Developer의 도움을 받아 해결하는 과정을 경험해보겠습니다. 이 대시보드는 100% Amazon Q Developer CLI를 활용하여 개발되었으며, AWS 계정 내의 보안 위협을 효과적으로 모니터링하고 대응할 수 있는 도구입니다.
![merged](https://github.com/user-attachments/assets/e910ddba-e8f0-4395-979e-71b84aaae19b)

## 실습 목표
- Amazon Q Developer CLI를 활용한 보안 대시보드 개발 방법 이해
- AWS 계정 내 보안 위협 요소 탐지 및 분석
- Amazon Q Developer를 통한 보안 위협 해결 방법 학습
- CLI 명령어를 활용한 효율적인 개발 방법 습득

## 사전 요구사항
- AI-Powered DevSecOps with Amazon Q Developer CLI Workshop 시작시 Preparation > 2. 실습환경 구성 과정에서 Amazon Q Developer CLI 를 설치한바 있으니 필요시 참고를 부탁드립니다.

## 실습 단계

### 1단계: Dashboard 접속과 CLI를 통한 개발과정 분석
1. 현재 각 실습자의 AWS Account에는 Cloudformation을 통해 이미 AWS Security Dashboard를 구성하는 리소스(EC2)와 개발코드(Streamlit)가 배포되어 있습니다. 여러분은 그 URL에 접근하여 Dashboard에 접근해 보고 구성된 기능과 실습용 AWS Account이 노출된 보안위협을 스캔해 볼 수 있습니다. 

2. 또한 이 AWS Security Dashboard이 Amazon Q Developer CLI를 활용하여 개발 되었음을 인지하고 개발과정에서 사용된 Prompt와 추가적인 활용법을 함께 확인해 봅니다.

### 2단계: 보안 위협 탐지 및 분석
AWS 환경에서의 보안 위협 탐지, 분석 및 해결 과정을 AWS Security Dashboard를 통해서 수행해 봅니다.
먼저 AWS IAM 자격 증명으로 대시보드에 로그인하고 Account내 IAM정보, CloudTrail정보를 조회해 보고 미리 설정된 S3 버킷 보안 설정, WAF 규칙, GuardDuty 알림 등을 분석하여 보안 위협을 스캔합니다. 발견된 위협은 Low(경
미), Medium(중간), High(심각) 등급으로 분류되며 이러한 문제해결을 위해 Amazon Q Developer CLI를 활용해 보는 과정입니다.

## AWS Security Dashboard 추가 개발 가이드 (선택)
1. 대시보드 기능 확장
   - 새로운 보안 메트릭 추가
   - 커스텀 알림 설정
   - 보고서 생성 기능

2. Amazon Q Developer CLI 활용 팁
   - 효율적인 프롬프트 작성 방법
   - CLI 명령어 최적화
   - 자동화 스크립트 개발

## 참고 자료
- [Amazon Q Developer CLI 공식 문서](https://aws.amazon.com/q/developer/?sc_icampaign=aware_q_dev&sc_ichannel=ha&sc_icontent=awssm-2842900-aware&sc_iplace=signin&trk=829bcc2c-e1f5-4e11-87d0-d2eb29f99620~ha_awssm-2842900-aware)
- [AWS 보안 모범 사례](https://aws.amazon.com/security)
- [Streamlit 공식 문서](https://docs.streamlit.io)
