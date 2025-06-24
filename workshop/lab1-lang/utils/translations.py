"""
다국어 지원을 위한 번역 데이터
"""

TRANSLATIONS = {
    'ko': {
        # 메인 UI
        'app_title': 'AWS 보안 대시보드',
        'language': '언어',
        'account_info': '계정 정보',
        'use_instance_profile': '인스턴스 프로파일 사용',
        'aws_region': 'AWS 리전',
        'aws_account_id': 'AWS 계정 ID',
        'aws_access_key': 'AWS Access Key ID',
        'aws_secret_key': 'AWS Secret Access Key',
        'profile_validation': '프로파일 검증',
        'account_validation': '계정 검증',
        'start_security_scan': '보안 스캔 시작',
        'account_reset': '계정 초기화',
        'last_scan': '마지막 스캔',
        
        # 탭 메뉴
        'iam_account_status': 'IAM 계정 현황',
        'cloudtrail_logs': 'CloudTrail 로그',
        'findings': '발견 사항',
        'recommendations': '권장 조치',
        
        # IAM 관련
        'iam_users': 'IAM 사용자',
        'iam_roles': 'IAM 역할',
        'iam_groups': 'IAM 그룹',
        'user_name': '사용자 이름',
        'role_name': '역할 이름',
        'group_name': '그룹 이름',
        'created_date': '생성일',
        'mfa_enabled': 'MFA 활성화',
        'trust_relationship': '신뢰 관계',
        'user_count': '사용자 수',
        
        # 보안 이슈
        's3_security_issues': 'S3 보안 이슈',
        'waf_security_issues': 'WAF 보안 이슈',
        'guardduty_findings': 'GuardDuty 탐지 결과',
        'guardduty_status': 'GuardDuty 상태',
        'issue_type': '이슈 유형',
        'resource': '리소스',
        'severity': '심각도',
        'description': '설명',
        'recommendation': '권장 조치',
        
        # 상태 메시지
        'scan_in_progress': 'AWS 계정 정보를 가져오는 중입니다...',
        'scan_completed': 'AWS 계정 정보를 성공적으로 가져왔습니다.',
        'scan_start_message': '보안 스캔을 시작하여 정보를 가져오세요.',
        'validation_failed': '검증 실패',
        'profile_validation_failed': '인스턴스 프로파일 검증 실패',
        'account_id_required': 'AWS 계정 ID를 입력해주세요.',
        'credentials_required': 'AWS Access Key와 Secret Key를 모두 입력해주세요.',
        'error_occurred': '오류 발생',
        
        # 정보 메시지
        'account_id_info': '계정 ID',
        'access_key_info': 'Access Key: ********',
        'region_info': '리전',
        'auth_method_info': '인증 방식',
        'instance_profile': '인스턴스 프로파일',
        'access_key': '액세스 키',
        'no_iam_users': 'IAM 사용자가 없습니다.',
        'no_iam_roles': 'IAM 역할이 없습니다.',
        'no_iam_groups': 'IAM 그룹이 없습니다.',
        'no_cloudtrail_events': 'CloudTrail 이벤트가 없습니다.',
        'no_s3_issues': 'S3 보안 이슈가 없습니다.',
        'no_waf_issues': 'WAF 보안 이슈가 없습니다.',
        'no_guardduty_findings': 'GuardDuty 탐지 결과가 없습니다.',
        
        # 버튼 및 액션
        'refresh': '새로고침',
        'export': '내보내기',
        'details': '상세보기',
        'download_csv': 'CSV로 다운로드',
        'get_recommendation': '권장 조치 받기',
        
        # GuardDuty 관련
        'guardduty_enabled': 'GuardDuty 활성화됨',
        'guardduty_disabled': 'GuardDuty 비활성화됨',
        'guardduty_unknown': 'GuardDuty 상태 알 수 없음',
        'guardduty_error': 'GuardDuty 오류',
        
        # 통계 정보
        'users_count': '사용자',
        'roles_count': '역할',
        'groups_count': '그룹',
        'users_without_mfa': 'MFA가 없는 사용자',
        'count_suffix': '개',
        'people_suffix': '명',
        
        # 날짜 형식
        'year': '년',
        'month': '월',
        'day': '일',
        
        # S3 보안 이슈 타입
        'PUBLIC_ACCESS_SETTINGS': '퍼블릭 액세스 설정',
        'ENCRYPTION': '암호화',
        'VERSIONING': '버전 관리',
        'LOGGING': '로깅',
        
        # S3 보안 이슈 설명
        'bucket_versioning_disabled': '버킷 버전 관리가 비활성화되어 있습니다.',
        'bucket_access_logging_disabled': '버킷 액세스 로깅이 비활성화되어 있습니다.',
        'bucket_public_access_not_blocked': '버킷의 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다.',
        'bucket_public_access_not_configured': '버킷에 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.',
        'bucket_encryption_not_configured': '버킷에 기본 암호화가 구성되지 않았습니다.',
        
        # S3 계정 수준 설정
        'account_level_public_access_missing': 'S3 계정 수준 퍼블릭 액세스 설정 누락',
        'account_level_public_access_settings_issue': 'S3 계정 수준 퍼블릭 액세스 설정 이슈',
        'account_level_public_access_block_not_fully_enabled': '계정 수준 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다.',
        'account_level_public_access_block_not_configured': '계정 수준 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.',
        
        # WAF 보안 이슈
        'waf_default_action_allow': 'WAF 기본 작업이 허용으로 설정됨',
        'waf_default_action_allow_desc': '웹 ACL의 기본 작업이 허용으로 설정되어 있습니다. 이는 명시적으로 차단되지 않은 모든 트래픽을 허용합니다.',
        'sql_injection_protection_missing': 'SQL 인젝션 보호 누락',
        'sql_injection_protection_missing_desc': '웹 ACL에 SQL 인젝션 보호 기능이 구성되지 않았습니다.',
        'xss_protection_missing': 'XSS 보호 누락',
        'xss_protection_missing_desc': '웹 ACL에 크로스 사이트 스크립팅(XSS) 보호 기능이 구성되지 않았습니다.',
        'common_threat_protection_missing': '일반적인 위협 보호 누락',
        'common_threat_protection_missing_desc': '웹 ACL에 AWS 관리형 규칙(AWSManagedRulesCommonRuleSet)이 구성되지 않았습니다.',
        'rate_limiting_protection_missing': '속도 제한 보호 누락',
        'rate_limiting_protection_missing_desc': '웹 ACL에 속도 기반 규칙이 구성되지 않아 DDoS 공격에 취약할 수 있습니다.',
        'waf_acl_not_associated': 'WAF 웹 ACL이 리소스에 연결되지 않음',
        'waf_acl_not_associated_desc': '웹 ACL이 어떤 리소스에도 연결되지 않았습니다. 이 ACL은 현재 트래픽을 보호하지 않습니다.',
        
        # S3 보안 이슈 관련
        'versioning': 'VERSIONING',
        'access_logging': 'ACCESS_LOGGING',
        'public_access_block': 'PUBLIC_ACCESS_BLOCK',
        'bucket_versioning_disabled': '버킷 버전 관리가 비활성화되었습니다.',
        'bucket_access_logging_disabled': '버킷에 액세스 로깅이 활성화되지 않았습니다.',
        'account_level_public_access_block_not_configured': '계정 수준의 S3 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.',
        
        # WAF 보안 이슈 관련
        'waf_regional': 'WAF REGIONAL',
        'waf_cloudfront': 'WAF CLOUDFRONT',
        'no_waf_web_acl': '웹 ACL 없음',
        'no_waf_web_acl_configured_regional': 'REGIONAL 범위에 구성된 WAF 웹 ACL이 없습니다. 웹 애플리케이션이 보호되지 않을 수 있습니다.',
        'no_waf_web_acl_configured_cloudfront': 'CLOUDFRONT 범위에 구성된 WAF 웹 ACL이 없습니다. 웹 애플리케이션이 보호되지 않을 수 있습니다.',
        
        # GuardDuty 관련
        'sample_threat': '샘플 위협 (실제 위협 없음)',
        'sample_threat_description': '이것은 샘플 위협입니다. 실제 GuardDuty 위협이 발견되지 않았습니다.',
        'finding_time': '발견 시간',
        
        # 권장사항 프롬프트
        'aws_security_issue_resolution': 'AWS 보안 이슈 해결 방법을 찾고 있습니다. 다음 이슈에 대한 해결 방법을 알려주세요:',
        'issue_type_label': '이슈 유형:',
        'affected_resource': '영향받는 리소스:',
        'issue_details': '이슈 상세 내용:',
        'resolution_info_request': '다음 정보를 포함한 해결 방법을 제시해주세요:',
        'severity_and_risk': '1. 이슈의 심각도와 잠재적 위험',
        'console_resolution_steps': '2. AWS 콘솔에서의 구체적인 해결 단계',
        'automation_methods': '3. AWS CLI나 CloudFormation을 사용한 자동화 방법',
        'verification_steps': '4. 해결 후 확인해야 할 검증 단계',
        'best_practices': '5. 향후 유사한 이슈를 방지하기 위한 모범 사례',
        'aws_best_practices_reference': 'AWS 보안 모범 사례와 최신 가이드라인을 참고하여 답변해주세요.',
        'prompt_for_amazon_q': 'Amazon Q CLI에 물어볼 프롬프트',
        
        # 추가 번역
        'bucket_versioning_disabled': '버킷에 버전 관리가 활성화되지 않았습니다.',
        'bucket_access_logging_disabled': '버킷에 액세스 로깅이 활성화되지 않았습니다.',
        'account_level_public_access_block_not_configured': '계정 수준의 S3 퍼블릭 액세스 차단 설정이 구성되지 않았습니다.',
        'account_level_public_access_block_not_fully_enabled': '계정 수준의 S3 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다.',
        
        # 메시지 템플릿
        'no_severity_issues_s3': '{severity} 심각도의 S3 보안 이슈가 없습니다.',
        'no_severity_issues_waf': '{severity} 심각도의 WAF 보안 이슈가 없습니다.',
        'no_severity_issues_guardduty': '{severity} 심각도의 GuardDuty 위협이 없습니다.',
        'no_high_severity_issues': 'HIGH 심각도의 보안 이슈가 발견되지 않았습니다.',
        'copy_prompt_instruction': '위 프롬프트를 복사하여 Amazon Q Dev Chat 터미널에서 사용하세요.',
    },
    'en': {
        # 메인 UI
        'app_title': 'AWS Security Dashboard',
        'language': 'Language',
        'account_info': 'Account Information',
        'use_instance_profile': 'Use Instance Profile',
        'aws_region': 'AWS Region',
        'aws_account_id': 'AWS Account ID',
        'aws_access_key': 'AWS Access Key ID',
        'aws_secret_key': 'AWS Secret Access Key',
        'profile_validation': 'Validate Profile',
        'account_validation': 'Validate Account',
        'start_security_scan': 'Start Security Scan',
        'account_reset': 'Reset Account',
        'last_scan': 'Last Scan',
        
        # 탭 메뉴
        'iam_account_status': 'IAM Account Status',
        'cloudtrail_logs': 'CloudTrail Logs',
        'findings': 'Findings',
        'recommendations': 'Recommendations',
        
        # IAM 관련
        'iam_users': 'IAM Users',
        'iam_roles': 'IAM Roles',
        'iam_groups': 'IAM Groups',
        'user_name': 'User Name',
        'role_name': 'Role Name',
        'group_name': 'Group Name',
        'created_date': 'Created Date',
        'mfa_enabled': 'MFA Enabled',
        'trust_relationship': 'Trust Relationship',
        'user_count': 'User Count',
        
        # 보안 이슈
        's3_security_issues': 'S3 Security Issues',
        'waf_security_issues': 'WAF Security Issues',
        'guardduty_findings': 'GuardDuty Findings',
        'guardduty_status': 'GuardDuty Status',
        'issue_type': 'Issue Type',
        'resource': 'Resource',
        'severity': 'Severity',
        'description': 'Description',
        'recommendation': 'Recommendation',
        
        # 상태 메시지
        'scan_in_progress': 'Retrieving AWS account information...',
        'scan_completed': 'AWS account information retrieved successfully.',
        'scan_start_message': 'Start security scan to retrieve information.',
        'validation_failed': 'Validation Failed',
        'profile_validation_failed': 'Instance profile validation failed',
        'account_id_required': 'Please enter AWS Account ID.',
        'credentials_required': 'Please enter both AWS Access Key and Secret Key.',
        'error_occurred': 'Error Occurred',
        
        # 정보 메시지
        'account_id_info': 'Account ID',
        'access_key_info': 'Access Key: ********',
        'region_info': 'Region',
        'auth_method_info': 'Authentication Method',
        'instance_profile': 'Instance Profile',
        'access_key': 'Access Key',
        'no_iam_users': 'No IAM users found.',
        'no_iam_roles': 'No IAM roles found.',
        'no_iam_groups': 'No IAM groups found.',
        'no_cloudtrail_events': 'No CloudTrail events found.',
        'no_s3_issues': 'No S3 security issues found.',
        'no_waf_issues': 'No WAF security issues found.',
        'no_guardduty_findings': 'No GuardDuty findings.',
        
        # 버튼 및 액션
        'refresh': 'Refresh',
        'export': 'Export',
        'details': 'Details',
        'download_csv': 'Download CSV',
        'get_recommendation': 'Get Recommendation',
        
        # GuardDuty 관련
        'guardduty_enabled': 'GuardDuty Enabled',
        'guardduty_disabled': 'GuardDuty Disabled',
        'guardduty_unknown': 'GuardDuty Status Unknown',
        'guardduty_error': 'GuardDuty Error',
        
        # 통계 정보
        'users_count': 'users',
        'roles_count': 'roles',
        'groups_count': 'groups',
        'users_without_mfa': 'Users without MFA',
        'count_suffix': '',
        'people_suffix': '',
        
        # 날짜 형식
        'year': '',
        'month': '',
        'day': '',
        
        # S3 보안 이슈 타입
        'PUBLIC_ACCESS_SETTINGS': 'Public Access Settings',
        'ENCRYPTION': 'Encryption',
        'VERSIONING': 'Versioning',
        'LOGGING': 'Logging',
        
        # S3 보안 이슈 설명
        'bucket_versioning_disabled': 'Bucket versioning is disabled.',
        'bucket_access_logging_disabled': 'Bucket access logging is disabled.',
        'bucket_public_access_not_blocked': 'Bucket public access block settings are not fully enabled.',
        'bucket_public_access_not_configured': 'Bucket public access block settings are not configured.',
        'bucket_encryption_not_configured': 'Default encryption is not configured for the bucket.',
        
        # S3 계정 수준 설정
        'account_level_public_access_missing': 'S3 Account-level Public Access Settings Missing',
        'account_level_public_access_settings_issue': 'S3 Account-level Public Access Settings Issue',
        'account_level_public_access_block_not_fully_enabled': 'Account-level public access block settings are not fully enabled.',
        'account_level_public_access_block_not_configured': 'Account-level public access block settings are not configured.',
        
        # WAF 보안 이슈
        'waf_default_action_allow': 'WAF Default Action Set to Allow',
        'waf_default_action_allow_desc': 'The web ACL default action is set to allow. This permits all traffic that is not explicitly blocked.',
        'sql_injection_protection_missing': 'SQL Injection Protection Missing',
        'sql_injection_protection_missing_desc': 'SQL injection protection is not configured in the web ACL.',
        'xss_protection_missing': 'XSS Protection Missing',
        'xss_protection_missing_desc': 'Cross-site scripting (XSS) protection is not configured in the web ACL.',
        'common_threat_protection_missing': 'Common Threat Protection Missing',
        'common_threat_protection_missing_desc': 'AWS managed rules (AWSManagedRulesCommonRuleSet) are not configured in the web ACL.',
        'rate_limiting_protection_missing': 'Rate Limiting Protection Missing',
        'rate_limiting_protection_missing_desc': 'Rate-based rules are not configured in the web ACL, making it vulnerable to DDoS attacks.',
        'waf_acl_not_associated': 'WAF Web ACL Not Associated with Resources',
        'waf_acl_not_associated_desc': 'The web ACL is not associated with any resources. This ACL is not currently protecting traffic.',
        
        # S3 보안 이슈 관련
        'versioning': 'VERSIONING',
        'access_logging': 'ACCESS_LOGGING',
        'public_access_block': 'PUBLIC_ACCESS_BLOCK',
        'bucket_versioning_disabled': 'Bucket versioning is disabled.',
        'bucket_access_logging_disabled': 'Access logging is not enabled for the bucket.',
        'account_level_public_access_block_not_configured': 'Account-level S3 public access block settings are not configured.',
        
        # WAF 보안 이슈 관련
        'waf_regional': 'WAF REGIONAL',
        'waf_cloudfront': 'WAF CLOUDFRONT',
        'no_waf_web_acl': 'No Web ACL',
        'no_waf_web_acl_configured_regional': 'No WAF Web ACL configured for REGIONAL scope. Web applications may not be protected.',
        'no_waf_web_acl_configured_cloudfront': 'No WAF Web ACL configured for CLOUDFRONT scope. Web applications may not be protected.',
        
        # GuardDuty 관련
        'sample_threat': 'Sample Threat (No Actual Threat)',
        'sample_threat_description': 'This is a sample threat. No actual GuardDuty threats were found.',
        'finding_time': 'Finding Time',
        
        # 권장사항 프롬프트
        'aws_security_issue_resolution': 'Looking for AWS security issue resolution. Please provide solutions for the following issue:',
        'issue_type_label': 'Issue Type:',
        'affected_resource': 'Affected Resource:',
        'issue_details': 'Issue Details:',
        'resolution_info_request': 'Please provide resolution methods including the following information:',
        'severity_and_risk': '1. Issue severity and potential risks',
        'console_resolution_steps': '2. Specific resolution steps in AWS Console',
        'automation_methods': '3. Automation methods using AWS CLI or CloudFormation',
        'verification_steps': '4. Verification steps after resolution',
        'best_practices': '5. Best practices to prevent similar issues in the future',
        'aws_best_practices_reference': 'Please refer to AWS security best practices and latest guidelines for your response.',
        'prompt_for_amazon_q': 'Prompt for Amazon Q CLI',
        
        # 추가 번역
        'bucket_versioning_disabled': 'Bucket versioning is not enabled.',
        'bucket_access_logging_disabled': 'Access logging is not enabled for the bucket.',
        'account_level_public_access_block_not_configured': 'Account-level S3 public access block settings are not configured.',
        'account_level_public_access_block_not_fully_enabled': 'Account-level S3 public access block settings are not fully enabled.',
        
        # 메시지 템플릿
        'no_severity_issues_s3': 'No S3 security issues with {severity} severity.',
        'no_severity_issues_waf': 'No WAF security issues with {severity} severity.',
        'no_severity_issues_guardduty': 'No GuardDuty threats with {severity} severity.',
        'no_high_severity_issues': 'No HIGH severity security issues found.',
        'copy_prompt_instruction': 'Copy the above prompt and use it in Amazon Q Dev Chat terminal.',
    }
}
