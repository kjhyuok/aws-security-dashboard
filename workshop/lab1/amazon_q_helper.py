import boto3
import json
import os
from datetime import datetime

def get_security_events():
    """
    보안 이벤트를 가져옵니다.
    """
    events = []
    
    # GuardDuty 탐지 결과 가져오기
    try:
        guardduty = boto3.client('guardduty')
        detectors = guardduty.list_detectors()
        
        if detectors['DetectorIds']:
            detector_id = detectors['DetectorIds'][0]
            findings = guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': 4
                        }
                    }
                },
                MaxResults=10
            )
            
            if findings['FindingIds']:
                finding_details = guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=findings['FindingIds']
                )
                
                for finding in finding_details['Findings']:
                    events.append({
                        'id': finding['Id'],
                        'type': 'GuardDuty',
                        'severity': finding['Severity'],
                        'title': finding['Title'],
                        'description': finding['Description'],
                        'time': finding['CreatedAt'],
                        'raw': finding
                    })
    except Exception as e:
        print(f"Error getting GuardDuty findings: {str(e)}")
    
    # WAF 로그 가져오기
    try:
        wafv2 = boto3.client('wafv2')
        web_acls = wafv2.list_web_acls(Scope='REGIONAL')
        
        for acl in web_acls.get('WebACLs', []):
            try:
                sampled_requests = wafv2.get_sampled_requests(
                    WebAclArn=acl['ARN'],
                    RuleMetricName='ALL',
                    Scope='REGIONAL',
                    MaxItems=10
                )
                
                for request in sampled_requests.get('SampledRequests', []):
                    if request.get('Action') == 'BLOCK':
                        events.append({
                            'id': request.get('RequestHeaderFields', {}).get('RequestId', 'unknown'),
                            'type': 'WAF',
                            'severity': 7,
                            'title': f"Blocked request by {request.get('RuleNameWithinRuleGroup', 'unknown rule')}",
                            'description': f"WAF blocked a request from {request.get('ClientIP', 'unknown')}",
                            'time': datetime.now().isoformat(),
                            'raw': request
                        })
            except Exception as e:
                print(f"Error getting WAF sampled requests: {str(e)}")
    except Exception as e:
        print(f"Error listing WAF web ACLs: {str(e)}")
    
    return events

def get_amazon_q_recommendation(security_event):
    """
    Amazon Q에 보안 이벤트에 대한 조치 방법을 물어봅니다.
    실제 Amazon Q API가 아닌 예시 코드입니다.
    """
    event_type = security_event.get('type', 'unknown')
    
    if event_type == 'GuardDuty':
        return {
            "recommendation": "이 GuardDuty 탐지 결과는 잠재적인 보안 위협을 나타냅니다. 다음 단계를 수행하세요:\n"
                             "1. 관련 EC2 인스턴스를 격리하세요\n"
                             "2. 보안 그룹을 검토하고 필요하지 않은 포트를 차단하세요\n"
                             "3. CloudTrail 로그를 검토하여 추가 의심스러운 활동이 있는지 확인하세요\n\n"
                             "Amazon Q에게 다음과 같이 물어보세요: '이 GuardDuty 탐지 결과를 어떻게 해결해야 하나요?'"
        }
    elif event_type == 'WAF':
        return {
            "recommendation": "WAF에서 차단된 요청이 감지되었습니다. 다음 단계를 수행하세요:\n"
                             "1. WAF 로그를 검토하여 공격 패턴을 파악하세요\n"
                             "2. IP 주소를 차단 목록에 추가하는 것을 고려하세요\n"
                             "3. 애플리케이션 취약점이 있는지 검토하세요\n\n"
                             "Amazon Q에게 다음과 같이 물어보세요: '이 WAF 차단 이벤트를 어떻게 분석해야 하나요?'"
        }
    else:
        return {
            "recommendation": "이 보안 이벤트를 조사하려면 다음 단계를 수행하세요:\n"
                             "1. CloudTrail 로그를 검토하여 관련 활동을 확인하세요\n"
                             "2. 관련 리소스의 구성을 검토하세요\n"
                             "3. 필요한 경우 보안 정책을 업데이트하세요\n\n"
                             "Amazon Q에게 다음과 같이 물어보세요: '이 보안 이벤트를 어떻게 조사해야 하나요?'"
        }
