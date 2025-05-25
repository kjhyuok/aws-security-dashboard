import boto3
from botocore.exceptions import ClientError
from datetime import datetime

def get_guardduty_findings(session, max_findings=100):
    """GuardDuty에서 위협 정보 가져오기"""
    guardduty = session.client('guardduty')
    
    try:
        # 모든 디텍터 ID 가져오기
        detectors = guardduty.list_detectors()
        findings = []
        
        for detector_id in detectors.get('DetectorIds', []):
            response = guardduty.list_findings(
                DetectorId=detector_id,
                MaxResults=max_findings,
                SortCriteria={'AttributeName': 'updatedAt', 'OrderBy': 'DESC'}
            )
            
            finding_ids = response.get('FindingIds', [])
            if finding_ids:
                details = guardduty.get_findings(
                    DetectorId=detector_id,
                    FindingIds=finding_ids
                )
                findings.extend(details.get('Findings', []))
        
        return findings
    except ClientError as e:
        print(f"GuardDuty API 호출 오류: {e}")
        return []

def format_guardduty_findings(findings):
    """GuardDuty 결과를 표시하기 쉬운 형식으로 변환"""
    formatted_findings = []
    
    for finding in findings:
        formatted_finding = {
            '제목': finding.get('Title', 'N/A'),
            '심각도': finding.get('Severity', 'N/A'),
            '유형': finding.get('Type', 'N/A'),
            '리소스 유형': finding.get('Resource', {}).get('ResourceType', 'N/A'),
            '리소스 ID': finding.get('Resource', {}).get('InstanceDetails', {}).get('InstanceId', 'N/A'),
            '설명': finding.get('Description', 'N/A'),
            '발견 시간': finding.get('CreatedAt', 'N/A'),
            '업데이트 시간': finding.get('UpdatedAt', 'N/A'),
            'ID': finding.get('Id', 'N/A')
        }
        formatted_findings.append(formatted_finding)
    
    return formatted_findings

def get_guardduty_status(session):
    """GuardDuty 활성화 상태 확인"""
    guardduty = session.client('guardduty')
    
    try:
        # 디텍터 목록 가져오기
        detectors = guardduty.list_detectors()
        detector_ids = detectors.get('DetectorIds', [])
        
        if not detector_ids:
            return {
                'status': 'NOT_CONFIGURED',
                'message': 'GuardDuty가 구성되지 않았습니다.',
                'detector_count': 0
            }
        
        # 각 디텍터의 상태 확인
        active_detectors = 0
        for detector_id in detector_ids:
            detector = guardduty.get_detector(DetectorId=detector_id)
            if detector.get('Status') == 'ENABLED':
                active_detectors += 1
        
        if active_detectors == len(detector_ids):
            return {
                'status': 'ACTIVE',
                'message': 'GuardDuty가 활성화되어 있습니다.',
                'detector_count': len(detector_ids)
            }
        elif active_detectors > 0:
            return {
                'status': 'PARTIALLY_ACTIVE',
                'message': f'일부 GuardDuty 디텍터만 활성화되어 있습니다. ({active_detectors}/{len(detector_ids)})',
                'detector_count': len(detector_ids),
                'active_count': active_detectors
            }
        else:
            return {
                'status': 'DISABLED',
                'message': 'GuardDuty가 비활성화되어 있습니다.',
                'detector_count': len(detector_ids)
            }
    
    except ClientError as e:
        print(f"GuardDuty 상태 확인 오류: {e}")
        return {
            'status': 'ERROR',
            'message': f'GuardDuty 상태 확인 중 오류 발생: {e}',
            'detector_count': 0
        }

def get_guardduty_recommendations(findings):
    """GuardDuty 결과에 대한 권장 조치 생성"""
    recommendations = []
    
    # 심각도별 결과 분류
    high_findings = [f for f in findings if f.get('Severity', 0) > 7]
    medium_findings = [f for f in findings if 4 < f.get('Severity', 0) <= 7]
    low_findings = [f for f in findings if f.get('Severity', 0) <= 4]
    
    # 심각도 높은 결과에 대한 권장 조치
    if high_findings:
        recommendations.append({
            'title': '심각한 GuardDuty 위협 발견',
            'description': f"{len(high_findings)}개의 심각한 보안 위협이 발견되었습니다. 즉시 조치가 필요합니다.",
            'severity': 'HIGH',
            'action': '발견된 위협을 검토하고 즉시 조치하세요.',
            'affected_resources': [f.get('리소스 ID', 'N/A') for f in high_findings]
        })
    
    # 중간 심각도 결과에 대한 권장 조치
    if medium_findings:
        recommendations.append({
            'title': '중요 GuardDuty 위협 발견',
            'description': f"{len(medium_findings)}개의 중요 보안 위협이 발견되었습니다. 조사가 필요합니다.",
            'severity': 'MEDIUM',
            'action': '발견된 위협을 검토하고 필요한 조치를 취하세요.',
            'affected_resources': [f.get('리소스 ID', 'N/A') for f in medium_findings]
        })
    
    # 낮은 심각도 결과에 대한 권장 조치
    if low_findings:
        recommendations.append({
            'title': '낮은 심각도 GuardDuty 위협 발견',
            'description': f"{len(low_findings)}개의 낮은 심각도 보안 위협이 발견되었습니다.",
            'severity': 'LOW',
            'action': '발견된 위협을 검토하고 필요한 경우 조치하세요.',
            'affected_resources': [f.get('리소스 ID', 'N/A') for f in low_findings]
        })
    
    return recommendations
