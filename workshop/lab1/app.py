import streamlit as st
import pandas as pd
from datetime import datetime
from utils.aws_client import create_aws_session, get_iam_info, get_cloudtrail_events
from utils.s3_security import get_s3_security_issues
from utils.waf_security import get_waf_security_issues
from utils.guardduty_security import get_guardduty_findings, format_guardduty_findings, get_guardduty_status

# Page configuration
st.set_page_config(page_title="AWS Security Dashboard", page_icon="🔒", layout="wide")

# Load CSS
with open('styles/main.css') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state variables
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False
if 'account_id' not in st.session_state:
    st.session_state.account_id = ""
if 'access_key' not in st.session_state:
    st.session_state.access_key = ""
if 'secret_key' not in st.session_state:
    st.session_state.secret_key = ""
if 'aws_region' not in st.session_state:
    st.session_state.aws_region = "ap-northeast-2"
if 'validated' not in st.session_state:
    st.session_state.validated = False
if 'use_instance_profile' not in st.session_state:
    st.session_state.use_instance_profile = False
if 's3_issues' not in st.session_state:
    st.session_state.s3_issues = []
if 'waf_issues' not in st.session_state:
    st.session_state.waf_issues = []
if 'guardduty_findings' not in st.session_state:
    st.session_state.guardduty_findings = []
if 'guardduty_status' not in st.session_state:
    st.session_state.guardduty_status = {'status': 'UNKNOWN', 'message': '아직 스캔되지 않음'}

# Sidebar
with st.sidebar:
    st.markdown("<h1 style='margin-top:0; font-size:1.5rem; color:#FF9900;'>AWS Security Dashboard</h1>", unsafe_allow_html=True)
    
    # Account information
    st.markdown("<p class='account-info-text'>계정 정보</p>", unsafe_allow_html=True)
    
    # 인스턴스 프로파일 사용 옵션 추가
    use_instance_profile = st.checkbox("인스턴스 프로파일 사용", value=st.session_state.use_instance_profile)
    st.session_state.use_instance_profile = use_instance_profile
    
    if not st.session_state.validated:
        if use_instance_profile:
            # 인스턴스 프로파일 사용 시 리전만 선택
            aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button("인스턴스 프로파일 검증", use_container_width=True)
            with login_col2:
                scan_button = st.button("보안 스캔 시작", use_container_width=True)
                
            if validate_button:
                try:
                    # 인스턴스 프로파일로 세션 생성
                    session = create_aws_session(use_profile=False, profile_name=None, access_key=None, secret_key=None, region=aws_region)
                    # 계정 ID 가져오기
                    sts_client = session.client('sts')
                    account_id = sts_client.get_caller_identity()["Account"]
                    
                    # 세션 상태에 저장
                    st.session_state.account_id = account_id
                    st.session_state.aws_region = aws_region
                    st.session_state.use_instance_profile = True
                    st.session_state.validated = True
                    st.rerun()
                except Exception as e:
                    st.error(f"인스턴스 프로파일 검증 실패: {e}")
        else:
            # 기존 방식 - 계정 정보 직접 입력
            account_id = st.text_input("AWS 계정 ID", placeholder="123456789012", key="input_account_id")
            access_key = st.text_input("AWS Access Key ID", type="password", key="input_access_key")
            secret_key = st.text_input("AWS Secret Access Key", type="password", key="input_secret_key")
            aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button("계정 검증", use_container_width=True)
            with login_col2:
                scan_button = st.button("보안 스캔 시작", use_container_width=True)
                
            if validate_button:
                if not account_id:
                    st.error("AWS 계정 ID를 입력해주세요.")
                elif not access_key or not secret_key:
                    st.error("AWS Access Key와 Secret Key를 모두 입력해주세요.")
                else:
                    # 세션 상태에 계정 정보 저장
                    st.session_state.account_id = account_id
                    st.session_state.aws_region = aws_region
                    st.session_state.access_key = access_key
                    st.session_state.secret_key = secret_key
                    st.session_state.validated = True
                    st.rerun()
    else:
        # 검증된 상태일 때 계정 정보 표시
        st.success(f"계정 ID: {st.session_state.account_id}")
        if not st.session_state.use_instance_profile:
            st.info("Access Key: ********")
        st.info(f"리전: {st.session_state.aws_region}")
        st.info(f"인증 방식: {'인스턴스 프로파일' if st.session_state.use_instance_profile else '액세스 키'}")
        
        reset_col1, reset_col2 = st.columns(2)
        with reset_col1:
            reset_button = st.button("계정 초기화", use_container_width=True)
        with reset_col2:
            scan_button = st.button("보안 스캔 시작", use_container_width=True)
            
        if reset_button:
            st.session_state.validated = False
            st.rerun()

# Main content
st.markdown('<h1 class="dashboard-title">AWS Security Dashboard</h1>', unsafe_allow_html=True)
st.markdown(f'<p class="last-scan">마지막 스캔: {datetime.now().strftime("%Y년 %m월 %d일 %H:%M")}</p>', unsafe_allow_html=True)

# Tabs
tabs = st.tabs(["👥 IAM 계정 현황", "📜 CloudTrail 로그", "⚠️ 발견 사항", "📝 권장 조치"])

# Scan button handler
if scan_button:
    try:
        with st.spinner("AWS 계정 정보를 가져오는 중입니다..."):
            # 인스턴스 프로파일 또는 입력된 자격 증명으로 세션 생성
            if st.session_state.use_instance_profile:
                aws_region = st.session_state.get("aws_region", "ap-northeast-2")
                session = create_aws_session(use_profile=False, profile_name=None, access_key=None, secret_key=None, region=aws_region)
            else:
                # 계정 검증 상태에 따라 계정 정보 가져오기
                if not st.session_state.validated:
                    account_id = st.session_state.get("input_account_id", "")
                    aws_region = st.session_state.get("input_aws_region", "ap-northeast-2")
                    access_key = st.session_state.get("input_access_key", "")
                    secret_key = st.session_state.get("input_secret_key", "")
                    
                    if not account_id:
                        st.sidebar.error("AWS 계정 ID를 입력해주세요.")
                        raise ValueError("AWS 계정 ID가 필요합니다.")
                    elif not access_key or not secret_key:
                        st.sidebar.error("AWS Access Key와 Secret Key를 모두 입력해주세요.")
                        raise ValueError("AWS 자격 증명이 필요합니다.")
                else:
                    account_id = st.session_state.account_id
                    aws_region = st.session_state.aws_region
                    access_key = st.session_state.access_key
                    secret_key = st.session_state.secret_key
                
                session = create_aws_session(use_profile=False, profile_name=None, access_key=access_key, secret_key=secret_key, region=aws_region)
            
            # Get IAM information
            iam_info = get_iam_info(session)
            st.session_state.iam_info = iam_info
            
            # Get CloudTrail events
            cloudtrail_events = get_cloudtrail_events(session)
            st.session_state.cloudtrail_events = cloudtrail_events
            
            # Get S3 security issues
            try:
                s3_issues = get_s3_security_issues(session)
                st.session_state.s3_issues = s3_issues
            except Exception as e:
                st.session_state.s3_issues = []
                print(f"S3 보안 이슈 스캔 실패: {e}")
            
            # Get WAF security issues
            try:
                waf_issues = get_waf_security_issues(session)
                st.session_state.waf_issues = waf_issues
            except Exception as e:
                st.session_state.waf_issues = []
                print(f"WAF 보안 이슈 스캔 실패: {e}")
            
            # Get GuardDuty findings
            try:
                guardduty_findings = get_guardduty_findings(session)
                st.session_state.guardduty_findings = format_guardduty_findings(guardduty_findings)
                
                # GuardDuty 상태 확인
                guardduty_status = get_guardduty_status(session)
                st.session_state.guardduty_status = guardduty_status
            except Exception as e:
                st.session_state.guardduty_findings = []
                st.session_state.guardduty_status = {'status': 'ERROR', 'message': str(e)}
                print(f"GuardDuty 정보 가져오기 실패: {e}")
            
            # Set scan completed flag
            st.session_state.scan_completed = True
            
            # Show success message
            st.sidebar.success(f"AWS 계정 정보를 성공적으로 가져왔습니다.")
            st.sidebar.info(f"사용자: {len(iam_info['users'])}명, 역할: {len(iam_info['roles'])}개, 그룹: {len(iam_info['groups'])}개")
            if 'users_without_mfa' in iam_info and iam_info['users_without_mfa']:
                st.sidebar.warning(f"MFA가 없는 사용자: {len(iam_info['users_without_mfa'])}명")
    
    except Exception as e:
        st.sidebar.error(f"오류 발생: {e}")

# IAM Account Status tab
with tabs[0]:
    st.markdown('<div class="card"><div class="card-header">IAM 계정 현황</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 IAM 계정 정보를 가져오세요.")
    else:
        iam_info = st.session_state.iam_info
        
        # Users Card
        st.markdown('<div class="card"><div class="card-header">IAM 사용자</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['users']:
            users_data = [{
                '사용자 이름': user['UserName'],
                '생성일': user['CreateDate'].strftime('%Y-%m-%d'),
                'MFA 활성화': '✅' if user.get('MFADevices') else '❌'
            } for user in iam_info['users']]
            st.dataframe(pd.DataFrame(users_data), use_container_width=True)
        else:
            st.info("IAM 사용자가 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Roles Card
        st.markdown('<div class="card"><div class="card-header">IAM 역할</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['roles']:
            roles_data = [{
                '역할 이름': role['RoleName'],
                '생성일': role['CreateDate'].strftime('%Y-%m-%d'),
                '신뢰 관계': role.get('AssumeRolePolicyDocument', {}).get('Statement', [{}])[0].get('Principal', {}).get('Service', 'N/A')
            } for role in iam_info['roles']]
            st.dataframe(pd.DataFrame(roles_data), use_container_width=True)
        else:
            st.info("IAM 역할이 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Groups Card
        st.markdown('<div class="card"><div class="card-header">IAM 그룹</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['groups']:
            groups_data = [{
                '그룹 이름': group['GroupName'],
                '생성일': group['CreateDate'].strftime('%Y-%m-%d'),
                '사용자 수': len(group.get('Users', []))
            } for group in iam_info['groups']]
            st.dataframe(pd.DataFrame(groups_data), use_container_width=True)
        else:
            st.info("IAM 그룹이 없습니다.")
        st.markdown('</div></div>', unsafe_allow_html=True)
    st.markdown('</div></div>', unsafe_allow_html=True)

# CloudTrail Logs tab
with tabs[1]:
    st.markdown('<div class="card"><div class="card-header">CloudTrail 로그</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 CloudTrail 로그를 가져오세요.")
    else:
        events = st.session_state.cloudtrail_events
        if events:
            event_data = [{
                '시간': event.get('EventTime').strftime('%Y-%m-%d %H:%M:%S'),
                '이벤트 이름': event.get('EventName'),
                '사용자': event.get('Username', 'N/A'),
                '소스 IP': event.get('SourceIPAddress', 'N/A')
            } for event in events]
            
            df = pd.DataFrame(event_data)
            st.dataframe(df, use_container_width=True)
            
            # CSV download
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="CSV로 다운로드",
                data=csv,
                file_name=f"cloudtrail_logs_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.warning("CloudTrail 이벤트가 없습니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Findings tab
with tabs[2]:
    st.markdown('<div class="card"><div class="card-header">발견 사항</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 보안 위협 정보를 가져오세요.")
    else:
        # S3, WAF, GuardDuty 탭 생성
        security_tabs = st.tabs(["S3 버킷", "WAF", "GuardDuty"])
        
        # S3 탭
        with security_tabs[0]:
            if hasattr(st.session_state, 's3_issues') and st.session_state.s3_issues:
                issues = st.session_state.s3_issues
                st.write(f"총 {len(issues)}개의 S3 보안 이슈가 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="s3_severity")
                
                if selected_severity != "모두 보기":
                    filtered_issues = [f for f in issues if f.get('severity') == selected_severity]
                else:
                    filtered_issues = issues
                
                if filtered_issues:
                    for issue in filtered_issues:
                        severity_class = "severity-high" if issue.get('severity') == "HIGH" else \
                                        "severity-medium" if issue.get('severity') == "MEDIUM" else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{issue.get('title', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {issue.get('description', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">발견 시간:</strong> {issue.get('created_at', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 S3 보안 이슈가 없습니다.")
            else:
                st.info("S3 보안 이슈가 발견되지 않았습니다.")
        
        # WAF 탭
        with security_tabs[1]:
            if hasattr(st.session_state, 'waf_issues') and st.session_state.waf_issues:
                issues = st.session_state.waf_issues
                st.write(f"총 {len(issues)}개의 WAF 보안 이슈가 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="waf_severity")
                
                if selected_severity != "모두 보기":
                    filtered_issues = [f for f in issues if f.get('severity') == selected_severity]
                else:
                    filtered_issues = issues
                
                if filtered_issues:
                    for issue in filtered_issues:
                        severity_class = "severity-high" if issue.get('severity') == "HIGH" else \
                                        "severity-medium" if issue.get('severity') == "MEDIUM" else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{issue.get('title', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {issue.get('description', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 WAF 보안 이슈가 없습니다.")
            else:
                st.info("WAF 보안 이슈가 발견되지 않았습니다.")
        
        # GuardDuty 탭
        with security_tabs[2]:
            # GuardDuty 상태 표시
            status = st.session_state.guardduty_status if hasattr(st.session_state, 'guardduty_status') else {'status': 'UNKNOWN', 'message': '알 수 없음'}
            
            status_class = "status-active" if status['status'] == 'ACTIVE' else \
                          "status-warning" if status['status'] == 'PARTIALLY_ACTIVE' else \
                          "status-error" if status['status'] in ['DISABLED', 'NOT_CONFIGURED'] else "status-warning"
            
            st.markdown(f"""
            <div class="status-indicator {status_class}" style="color: #000000;">
                <strong style="color: #000000;">GuardDuty 상태:</strong> {status['status']} - {status['message']}
            </div>
            """, unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'guardduty_findings') and st.session_state.guardduty_findings:
                findings = st.session_state.guardduty_findings
                st.write(f"총 {len(findings)}개의 GuardDuty 위협이 발견되었습니다.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "높음 (7-10)", "중간 (4-7)", "낮음 (0-4)"]
                selected_severity = st.selectbox("심각도 필터", severity_options, key="gd_severity")
                
                if selected_severity == "높음 (7-10)":
                    filtered_findings = [f for f in findings if f.get('심각도', 0) > 7]
                elif selected_severity == "중간 (4-7)":
                    filtered_findings = [f for f in findings if 4 < f.get('심각도', 0) <= 7]
                elif selected_severity == "낮음 (0-4)":
                    filtered_findings = [f for f in findings if f.get('심각도', 0) <= 4]
                else:
                    filtered_findings = findings
                
                if filtered_findings:
                    for finding in filtered_findings:
                        severity_value = finding.get('심각도', 0)
                        severity_class = "severity-high" if severity_value > 7 else \
                                        "severity-medium" if severity_value > 4 else "severity-low"
                        
                        st.markdown(f"""
                        <div class="finding-item {severity_class}">
                            <h3 style="color: #000000;">{finding.get('제목', 'N/A')}</h3>
                            <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {finding.get('심각도', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">유형:</strong> {finding.get('유형', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">리소스:</strong> {finding.get('리소스 유형', 'N/A')} - {finding.get('리소스 ID', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {finding.get('설명', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">발견 시간:</strong> {finding.get('발견 시간', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(f"{selected_severity} 심각도의 GuardDuty 위협이 없습니다.")
            else:
                if status['status'] in ['ACTIVE', 'PARTIALLY_ACTIVE']:
                    st.info("GuardDuty 위협이 발견되지 않았습니다.")
                else:
                    st.warning("GuardDuty가 활성화되지 않았거나 구성되지 않았습니다. AWS 콘솔에서 GuardDuty를 활성화하세요.")
                    
                    # GuardDuty 활성화 방법 안내
                    with st.expander("GuardDuty 활성화 방법"):
                        st.markdown("""
                        1. AWS 콘솔에 로그인합니다.
                        2. GuardDuty 서비스로 이동합니다.
                        3. '시작하기' 또는 'GuardDuty 활성화' 버튼을 클릭합니다.
                        4. 설정을 검토하고 '활성화'를 클릭합니다.
                        
                        GuardDuty는 30일 무료 평가판을 제공하며, 이후에는 사용량에 따라 요금이 부과됩니다.
                        """)
    st.markdown('</div></div>', unsafe_allow_html=True)

# Recommendations tab
with tabs[3]:
    st.markdown('<div class="card"><div class="card-header">권장 조치</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info("보안 스캔을 시작하여 권장 조치를 확인하세요.")
    else:
        # 권장 조치 목록
        recommendations = []
        
        # IAM 관련 권장 조치
        iam_info = st.session_state.iam_info if hasattr(st.session_state, 'iam_info') else {}
        
        # MFA가 없는 사용자 확인
        if 'users_without_mfa' in iam_info and iam_info['users_without_mfa']:
            recommendations.append({
                'title': 'MFA가 없는 사용자 발견',
                'description': f"{len(iam_info['users_without_mfa'])}명의 사용자가 MFA를 사용하지 않고 있습니다. 모든 IAM 사용자에게 MFA를 활성화하는 것이 좋습니다.",
                'severity': 'HIGH',
                'action': 'AWS 콘솔에서 IAM > 사용자로 이동하여 MFA 디바이스를 등록하세요.',
                'affected_resources': iam_info['users_without_mfa']
            })
        
        # S3 관련 권장 조치
        if hasattr(st.session_state, 's3_issues') and st.session_state.s3_issues:
            high_issues = [i for i in st.session_state.s3_issues if i.get('severity') == 'HIGH']
            if high_issues:
                recommendations.append({
                    'title': 'S3 버킷 보안 취약점 발견',
                    'description': f"{len(high_issues)}개의 심각한 S3 버킷 보안 취약점이 발견되었습니다. 즉시 조치가 필요합니다.",
                    'severity': 'HIGH',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 조치하세요.',
                    'affected_resources': [i.get('resource_id', 'N/A') for i in high_issues]
                })
        
        # WAF 관련 권장 조치
        if hasattr(st.session_state, 'waf_issues') and st.session_state.waf_issues:
            high_issues = [i for i in st.session_state.waf_issues if i.get('severity') == 'HIGH']
            if high_issues:
                recommendations.append({
                    'title': 'WAF 보안 구성 이슈 발견',
                    'description': f"{len(high_issues)}개의 심각한 WAF 보안 구성 이슈가 발견되었습니다. 웹 애플리케이션이 적절히 보호되지 않을 수 있습니다.",
                    'severity': 'HIGH',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 WAF 규칙을 추가하세요.',
                    'affected_resources': [i.get('resource_id', 'N/A') for i in high_issues]
                })
        
        # GuardDuty 관련 권장 조치
        if hasattr(st.session_state, 'guardduty_findings') and st.session_state.guardduty_findings:
            high_findings = [f for f in st.session_state.guardduty_findings if f.get('심각도', 0) > 7]
            if high_findings:
                recommendations.append({
                    'title': 'GuardDuty에서 심각한 위협 발견',
                    'description': f"{len(high_findings)}개의 심각한 보안 위협이 GuardDuty에서 발견되었습니다. 즉시 조치가 필요합니다.",
                    'severity': 'CRITICAL',
                    'action': '발견 사항 탭에서 자세한 내용을 확인하고 조치하세요.',
                    'affected_resources': [f.get('리소스 ID', 'N/A') for f in high_findings]
                })
        
        # 권장 조치 표시
        if recommendations:
            for rec in recommendations:
                severity_class = "severity-high" if rec['severity'] in ["CRITICAL", "HIGH"] else \
                                "severity-medium" if rec['severity'] == "MEDIUM" else "severity-low"
                
                st.markdown(f"""
                <div class="finding-item {severity_class}">
                    <h3 style="color: #000000;">{rec['title']}</h3>
                    <p style="color: #000000;"><strong style="color: #000000;">심각도:</strong> {rec['severity']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">설명:</strong> {rec['description']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">권장 조치:</strong> {rec['action']}</p>
                    <p style="color: #000000;"><strong style="color: #000000;">영향 받는 리소스:</strong> {', '.join(rec['affected_resources'][:5])}{'...' if len(rec['affected_resources']) > 5 else ''}</p>
                </div>
                """, unsafe_allow_html=True)
                
                # Amazon Q에게 조치 방법 물어보기 버튼
                if st.button(f"Amazon Q에게 '{rec['title']}' 조치 방법 물어보기", key=f"ask_q_{recommendations.index(rec)}"):
                    st.info("Amazon Q에게 조치 방법을 물어보는 기능은 현재 개발 중입니다.")
        else:
            st.success("모든 보안 검사를 통과했습니다! 현재 권장 조치가 없습니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Footer
st.markdown('<p style="text-align: center; color: #666666; font-size: 0.8rem; margin-top: 30px;">AWS 운영자를 위한 보안 대시보드 | Amazon Q 핸즈온 워크샵</p>', unsafe_allow_html=True)
