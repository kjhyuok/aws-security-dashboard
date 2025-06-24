"""
스마트 다국어 지원 시스템
하드코딩된 번역 + 패턴 기반 번역 + 폴백
"""

import re
from .i18n import get_current_language
from .translations import TRANSLATIONS

# 동적 번역 패턴
DYNAMIC_PATTERNS = {
    'ko_to_en': [
        # S3 패턴
        (r'S3 버킷 보안 이슈: (.+)', r'S3 Security Issues: \1'),
        (r'S3 계정 수준 (.+)', r'S3 Account-level \1'),
        (r'버킷의? (.+?)이?가? (.+?)되어? ?있습니다', r'Bucket \1 is \2d'),
        (r'버킷에 (.+?)이?가? (.+?)되지 않았습니다', r'\1 is not \2d for the bucket'),
        (r'버킷 (.+?)이?가? (.+?)되어 있습니다', r'Bucket \1 is \2d'),
        
        # WAF 패턴  
        (r'WAF (.+) 보호 누락', r'WAF \1 Protection Missing'),
        (r'웹 ACL "(.+?)"의? (.+)', r'\2 of web ACL "\1"'),
        (r'웹 ACL "(.+?)"에 (.+)', r'\2 in web ACL "\1"'),
        
        # 일반 패턴
        (r'(.+) 보안 이슈', r'\1 Security Issues'),
        (r'(.+?)이?가? 활성화되지 않았습니다', r'\1 is not enabled'),
        (r'(.+?)이?가? 비활성화되어 있습니다', r'\1 is disabled'),
        (r'(.+?)이?가? 구성되지 않았습니다', r'\1 is not configured'),
        (r'(.+) 설정', r'\1 Settings'),
        (r'(.+) 누락', r'\1 Missing'),
    ]
}

# 단어 사전
WORD_DICTIONARY = {
    'ko_to_en': {
        # 기술 용어
        '버전 관리': 'Versioning',
        '버전관리': 'Versioning', 
        '암호화': 'Encryption',
        '로깅': 'Logging',
        '퍼블릭 액세스': 'Public Access',
        '퍼블릭액세스': 'Public Access',
        '액세스': 'Access',
        
        # 상태/동작
        '설정': 'Settings',
        '구성': 'Configuration',
        '활성화': 'Enabled',
        '비활성화': 'Disabled',
        '차단': 'Block',
        '허용': 'Allow',
        '연결': 'Associated',
        '누락': 'Missing',
        '보호': 'Protection',
        
        # 보안 관련
        '보안': 'Security',
        '위협': 'Threat',
        '취약점': 'Vulnerability',
        '취약성': 'Vulnerability',
        '심각도': 'Severity',
        '이슈': 'Issues',
        '문제': 'Issues',
        
        # 심각도
        '높음': 'High',
        '중간': 'Medium', 
        '낮음': 'Low',
        'HIGH': 'High',
        'MEDIUM': 'Medium',
        'LOW': 'Low',
        
        # AWS 서비스
        '버킷': 'Bucket',
        '계정': 'Account',
        '리소스': 'Resource',
        '규칙': 'Rule',
        '정책': 'Policy',
        
        # 공격 유형
        'SQL 인젝션': 'SQL Injection',
        'XSS': 'XSS',
        '크로스 사이트 스크립팅': 'Cross-site Scripting',
        'DDoS': 'DDoS',
        '속도 제한': 'Rate Limiting',
        '속도제한': 'Rate Limiting',
    }
}

def smart_get_text(key_or_text, force_translate=False):
    """
    스마트 번역 함수
    1. 하드코딩된 번역 우선 확인
    2. 패턴 기반 번역 시도
    3. 단어별 번역 시도
    4. 원본 반환
    """
    current_lang = get_current_language()
    
    # 한국어면 원본 반환
    if current_lang == 'ko':
        return key_or_text
    
    # 1. 하드코딩된 번역 확인
    if key_or_text in TRANSLATIONS.get(current_lang, {}):
        return TRANSLATIONS[current_lang][key_or_text]
    
    # 2. 영어 번역 시도
    if current_lang == 'en':
        return translate_korean_to_english(key_or_text)
    
    # 3. 기본값 반환
    return key_or_text

def translate_korean_to_english(text):
    """한국어를 영어로 번역 - 단어별 치환 방식"""
    if not text or not isinstance(text, str):
        return text
    
    translated = text
    
    # 단어별 번역 (순서 중요 - 긴 구문부터)
    replacements = [
        # 완전한 구문
        ('S3 버킷 보안 이슈:', 'S3 Security Issues:'),
        ('S3 계정 수준', 'S3 Account-level'),
        ('버킷 버전 관리가 비활성화되어 있습니다', 'Bucket versioning is disabled'),
        ('버킷 액세스 로깅이 비활성화되어 있습니다', 'Bucket access logging is disabled'),
        ('버킷의 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다', 'Bucket public access block settings are not fully enabled'),
        ('버킷에 퍼블릭 액세스 차단 설정이 구성되지 않았습니다', 'Bucket public access block settings are not configured'),
        ('버킷에 기본 암호화가 구성되지 않았습니다', 'Default encryption is not configured for the bucket'),
        ('계정 수준 퍼블릭 액세스 차단 설정이 완전히 활성화되지 않았습니다', 'Account-level public access block settings are not fully enabled'),
        ('계정 수준 퍼블릭 액세스 차단 설정이 구성되지 않았습니다', 'Account-level public access block settings are not configured'),
        
        # WAF 관련
        ('웹 ACL', 'Web ACL'),
        ('기본 작업이 허용으로 설정되어 있습니다', 'default action is set to allow'),
        ('명시적으로 차단되지 않은 모든 트래픽을 허용합니다', 'permits all traffic that is not explicitly blocked'),
        ('SQL 인젝션 보호 기능이 구성되지 않았습니다', 'SQL injection protection is not configured'),
        ('크로스 사이트 스크립팅(XSS) 보호 기능이 구성되지 않았습니다', 'Cross-site scripting (XSS) protection is not configured'),
        ('AWS 관리형 규칙(AWSManagedRulesCommonRuleSet)이 구성되지 않았습니다', 'AWS managed rules (AWSManagedRulesCommonRuleSet) are not configured'),
        ('속도 기반 규칙이 구성되지 않아 DDoS 공격에 취약할 수 있습니다', 'Rate-based rules are not configured, making it vulnerable to DDoS attacks'),
        ('어떤 리소스에도 연결되지 않았습니다', 'is not associated with any resources'),
        ('현재 트래픽을 보호하지 않습니다', 'is not currently protecting traffic'),
        
        # 개별 단어/구문
        ('버전 관리', 'Versioning'),
        ('퍼블릭 액세스', 'Public Access'),
        ('암호화', 'Encryption'),
        ('로깅', 'Logging'),
        ('설정', 'Settings'),
        ('보안 이슈', 'Security Issues'),
        ('보안', 'Security'),
        ('이슈', 'Issues'),
        ('누락', 'Missing'),
        ('보호', 'Protection'),
        ('활성화', 'Enabled'),
        ('비활성화', 'Disabled'),
        ('구성', 'Configuration'),
        ('차단', 'Block'),
        ('허용', 'Allow'),
        ('연결', 'Associated'),
        ('버킷', 'Bucket'),
        ('계정', 'Account'),
        ('리소스', 'Resource'),
        ('규칙', 'Rule'),
        ('정책', 'Policy'),
        ('위협', 'Threat'),
        ('취약점', 'Vulnerability'),
        ('심각도', 'Severity'),
        ('높음', 'High'),
        ('중간', 'Medium'),
        ('낮음', 'Low'),
        ('SQL 인젝션', 'SQL Injection'),
        ('속도 제한', 'Rate Limiting'),
    ]
    
    # 순차적으로 치환
    for korean, english in replacements:
        if korean in translated:
            translated = translated.replace(korean, english)
    
    return translated

def get_smart_title(issue_type, base_service=""):
    """이슈 타입에 따른 스마트 제목 생성"""
    current_lang = get_current_language()
    
    if current_lang == 'ko':
        if base_service:
            return f"{base_service} 보안 이슈: {issue_type}"
        return issue_type
    else:  # 영어
        # 이슈 타입 번역
        translated_type = smart_get_text(issue_type)
        if base_service:
            translated_service = smart_get_text(base_service)
            return f"{translated_service} Security Issues: {translated_type}"
        return translated_type
