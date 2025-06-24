import boto3
from botocore.exceptions import ClientError
from .i18n import get_text

def get_waf_security_issues(session):
    """WAF 구성의 보안 이슈를 스캔합니다."""
    issues = []
    
    # WAF v2 (WAFV2) 클라이언트 생성
    wafv2 = session.client('wafv2')
    
    # 리전 및 CloudFront 범위에서 웹 ACL 확인
    scopes = ['REGIONAL', 'CLOUDFRONT']
    
    for scope in scopes:
        try:
            # 웹 ACL 목록 가져오기
            response = wafv2.list_web_acls(Scope=scope)
            web_acls = response.get('WebACLs', [])
            
            if not web_acls:
                # 웹 ACL이 없는 경우 이슈 추가
                issues.append({
                    'resource_type': 'WAF',
                    'resource_id': f'WAF_{scope}',
                    'title': f'WAF {scope} {get_text("no_waf_web_acl")}',
                    'severity': 'MEDIUM',
                    'description': get_text(f'no_waf_web_acl_configured_{scope.lower()}'),
                    'created_at': 'N/A'
                })
                continue
            
            # 각 웹 ACL 분석
            for acl in web_acls:
                acl_id = acl['Id']
                acl_name = acl['Name']
                
                # 웹 ACL 세부 정보 가져오기
                acl_detail = wafv2.get_web_acl(
                    Name=acl_name,
                    Scope=scope,
                    Id=acl_id
                )
                
                # 규칙 그룹 확인
                rules = acl_detail.get('WebACL', {}).get('Rules', [])
                
                # 기본 작업 확인
                default_action = acl_detail.get('WebACL', {}).get('DefaultAction', {})
                if 'Allow' in default_action:
                    issues.append({
                        'resource_type': 'WAF_ACL',
                        'resource_id': acl_name,
                        'title': get_text('waf_default_action_allow'),
                        'severity': 'MEDIUM',
                        'description': f'{get_text("waf_default_action_allow_desc")} (ACL: "{acl_name}")',
                        'created_at': 'N/A'
                    })
                
                # 필수 보호 기능 확인
                protection_checks = {
                    'SQL_INJECTION': False,
                    'XSS': False,
                    'BAD_INPUTS': False,
                    'RATE_LIMITING': False
                }
                
                for rule in rules:
                    statement = rule.get('Statement', {})
                    
                    # SQL 인젝션 보호 확인
                    if 'SqliMatchStatement' in statement:
                        protection_checks['SQL_INJECTION'] = True
                    
                    # XSS 보호 확인
                    if 'XssMatchStatement' in statement:
                        protection_checks['XSS'] = True
                    
                    # 속도 제한 확인
                    if 'RateBasedStatement' in statement:
                        protection_checks['RATE_LIMITING'] = True
                    
                    # AWS 관리형 규칙 그룹 확인
                    if 'ManagedRuleGroupStatement' in statement:
                        vendor = statement['ManagedRuleGroupStatement'].get('VendorName', '')
                        name = statement['ManagedRuleGroupStatement'].get('Name', '')
                        
                        if vendor == 'AWS' and 'CommonRuleSet' in name:
                            protection_checks['BAD_INPUTS'] = True
                
                # 누락된 보호 기능에 대한 이슈 추가
                for check, enabled in protection_checks.items():
                    if not enabled:
                        issue_title = ''
                        issue_desc = ''
                        
                        if check == 'SQL_INJECTION':
                            issue_title = get_text('sql_injection_protection_missing')
                            issue_desc = f'{get_text("sql_injection_protection_missing_desc")} (ACL: "{acl_name}")'
                        elif check == 'XSS':
                            issue_title = get_text('xss_protection_missing')
                            issue_desc = f'{get_text("xss_protection_missing_desc")} (ACL: "{acl_name}")'
                        elif check == 'BAD_INPUTS':
                            issue_title = get_text('common_threat_protection_missing')
                            issue_desc = f'{get_text("common_threat_protection_missing_desc")} (ACL: "{acl_name}")'
                        elif check == 'RATE_LIMITING':
                            issue_title = get_text('rate_limiting_protection_missing')
                            issue_desc = f'{get_text("rate_limiting_protection_missing_desc")} (ACL: "{acl_name}")'
                        
                        issues.append({
                            'resource_type': 'WAF_ACL',
                            'resource_id': acl_name,
                            'title': issue_title,
                            'severity': 'HIGH' if check in ['SQL_INJECTION', 'XSS'] else 'MEDIUM',
                            'description': issue_desc,
                            'created_at': 'N/A'
                        })
                
                # 리소스 연결 확인
                try:
                    resources = wafv2.list_resources_for_web_acl(
                        WebACLArn=acl_detail['WebACL']['ARN'],
                        ResourceType='APPLICATION_LOAD_BALANCER' if scope == 'REGIONAL' else 'CLOUDFRONT'
                    )
                    
                    if not resources.get('ResourceArns'):
                        issues.append({
                            'resource_type': 'WAF_ACL',
                            'resource_id': acl_name,
                            'title': get_text('waf_acl_not_associated'),
                            'severity': 'LOW',
                            'description': f'{get_text("waf_acl_not_associated_desc")} (ACL: "{acl_name}")',
                            'created_at': 'N/A'
                        })
                except ClientError as e:
                    print(f"리소스 연결 확인 실패 (ACL: {acl_name}): {e}")
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'WAFNonexistentItemException':
                print(f"WAF {scope} 범위에 웹 ACL이 없습니다.")
            else:
                print(f"WAF {scope} 웹 ACL 확인 중 오류 발생: {e}")
    
    return issues
