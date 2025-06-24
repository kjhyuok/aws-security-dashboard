import streamlit as st
import pandas as pd
from datetime import datetime, timezone, timedelta
import subprocess
from utils.aws_client import create_aws_session, get_iam_info, get_cloudtrail_events
from utils.s3_security import get_s3_security_issues
from utils.waf_security import get_waf_security_issues
from utils.guardduty_security import get_guardduty_findings, format_guardduty_findings, get_guardduty_status
from utils.i18n import init_language, get_text, language_selector, format_datetime, format_date, get_count_text, get_current_language

def get_q_recommendation(issue_type, issue_details, resource):
    """
    Amazon Q CLI에 물어볼 수 있는 상세한 프롬프트를 생성합니다.
    """
    prompt = f"""
{get_text('aws_security_issue_resolution')}

{get_text('issue_type_label')} {issue_type}
{get_text('affected_resource')} {resource}
{get_text('issue_details')} {issue_details}

{get_text('resolution_info_request')}
{get_text('severity_and_risk')}
{get_text('console_resolution_steps')}
{get_text('automation_methods')}
{get_text('verification_steps')}
{get_text('best_practices')}

{get_text('aws_best_practices_reference')}
"""
    return prompt

# Page configuration
st.set_page_config(page_title="AWS Security Dashboard", page_icon="🔒", layout="wide")

# Initialize language support
init_language()

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
    # Language selector at the top
    language_selector()
    
    st.markdown(f"<h1 style='margin-top:0; font-size:1.5rem; color:#FF9900;'>{get_text('app_title')}</h1>", unsafe_allow_html=True)
    
    # Account information
    st.markdown(f"<p class='account-info-text'>{get_text('account_info')}</p>", unsafe_allow_html=True)
    
    # 인스턴스 프로파일 사용 옵션 추가
    use_instance_profile = st.checkbox(get_text('use_instance_profile'), value=st.session_state.use_instance_profile)
    st.session_state.use_instance_profile = use_instance_profile
    
    if not st.session_state.validated:
        if use_instance_profile:
            # 인스턴스 프로파일 사용 시 리전만 선택
            aws_region = st.selectbox(get_text('aws_region'), ["us-east-1", "us-west-2", "ap-northeast-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button(get_text('profile_validation'), use_container_width=True)
            with login_col2:
                scan_button = st.button(get_text('start_security_scan'), use_container_width=True)
                
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
                    st.error(f"{get_text('profile_validation_failed')}: {e}")
        else:
            # 기존 방식 - 계정 정보 직접 입력
            account_id = st.text_input(get_text('aws_account_id'), placeholder="123456789012", key="input_account_id")
            access_key = st.text_input(get_text('aws_access_key'), type="password", key="input_access_key")
            secret_key = st.text_input(get_text('aws_secret_key'), type="password", key="input_secret_key")
            aws_region = st.selectbox(get_text('aws_region'), ["ap-northeast-2", "us-east-1", "us-west-2"], key="input_aws_region")
            
            login_col1, login_col2 = st.columns(2)
            with login_col1:
                validate_button = st.button(get_text('account_validation'), use_container_width=True)
            with login_col2:
                scan_button = st.button(get_text('start_security_scan'), use_container_width=True)
                
            if validate_button:
                if not account_id:
                    st.error(get_text('account_id_required'))
                elif not access_key or not secret_key:
                    st.error(get_text('credentials_required'))
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
        st.success(f"{get_text('account_id_info')}: {st.session_state.account_id}")
        if not st.session_state.use_instance_profile:
            st.info(get_text('access_key_info'))
        st.info(f"{get_text('region_info')}: {st.session_state.aws_region}")
        st.info(f"{get_text('auth_method_info')}: {get_text('instance_profile') if st.session_state.use_instance_profile else get_text('access_key')}")
        
        reset_col1, reset_col2 = st.columns(2)
        with reset_col1:
            reset_button = st.button(get_text('account_reset'), use_container_width=True)
        with reset_col2:
            scan_button = st.button(get_text('start_security_scan'), use_container_width=True)
            
        if reset_button:
            st.session_state.validated = False
            st.rerun()

# Main content
st.markdown(f'<h1 class="dashboard-title">{get_text("app_title")}</h1>', unsafe_allow_html=True)
st.markdown(f'<p class="last-scan">{get_text("last_scan")}: {format_datetime(datetime.now())}</p>', unsafe_allow_html=True)

# Tabs
tabs = st.tabs([f"👥 {get_text('iam_account_status')}", f"📜 {get_text('cloudtrail_logs')}", f"⚠️ {get_text('findings')}", f"📝 {get_text('recommendations')}"])

# Scan button handler
if scan_button:
    try:
        with st.spinner(get_text('scan_in_progress')):
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
                        st.sidebar.error(get_text('account_id_required'))
                        raise ValueError("AWS 계정 ID가 필요합니다.")
                    elif not access_key or not secret_key:
                        st.sidebar.error(get_text('credentials_required'))
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
            st.sidebar.success(get_text('scan_completed'))
            st.sidebar.info(f"{get_text('users_count')}: {get_count_text(len(iam_info['users']), 'users')}, {get_text('roles_count')}: {get_count_text(len(iam_info['roles']), 'roles')}, {get_text('groups_count')}: {get_count_text(len(iam_info['groups']), 'groups')}")
            if 'users_without_mfa' in iam_info and iam_info['users_without_mfa']:
                st.sidebar.warning(f"{get_text('users_without_mfa')}: {get_count_text(len(iam_info['users_without_mfa']), 'users_without_mfa')}")
    
    except Exception as e:
        st.sidebar.error(f"{get_text('error_occurred')}: {e}")

# IAM Account Status tab
with tabs[0]:
    st.markdown(f'<div class="card"><div class="card-header">{get_text("iam_account_status")}</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info(get_text('scan_start_message'))
    else:
        iam_info = st.session_state.iam_info
        
        # Users Card
        st.markdown(f'<div class="card"><div class="card-header">{get_text("iam_users")}</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['users']:
            users_data = [{
                get_text('user_name'): user['UserName'],
                get_text('created_date'): format_date(user['CreateDate']),
                get_text('mfa_enabled'): '✅' if user.get('MFADevices') else '❌'
            } for user in iam_info['users']]
            st.dataframe(pd.DataFrame(users_data), use_container_width=True)
        else:
            st.info(get_text('no_iam_users'))
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Roles Card
        st.markdown(f'<div class="card"><div class="card-header">{get_text("iam_roles")}</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['roles']:
            roles_data = [{
                get_text('role_name'): role['RoleName'],
                get_text('created_date'): format_date(role['CreateDate']),
                get_text('trust_relationship'): role.get('AssumeRolePolicyDocument', {}).get('Statement', [{}])[0].get('Principal', {}).get('Service', 'N/A')
            } for role in iam_info['roles']]
            st.dataframe(pd.DataFrame(roles_data), use_container_width=True)
        else:
            st.info(get_text('no_iam_roles'))
        st.markdown('</div></div>', unsafe_allow_html=True)
        
        # Groups Card
        st.markdown(f'<div class="card"><div class="card-header">{get_text("iam_groups")}</div><div class="card-content">', unsafe_allow_html=True)
        if iam_info['groups']:
            groups_data = [{
                get_text('group_name'): group['GroupName'],
                get_text('created_date'): format_date(group['CreateDate']),
                get_text('user_count'): len(group.get('Users', []))
            } for group in iam_info['groups']]
            st.dataframe(pd.DataFrame(groups_data), use_container_width=True)
        else:
            st.info(get_text('no_iam_groups'))
        st.markdown('</div></div>', unsafe_allow_html=True)
    st.markdown('</div></div>', unsafe_allow_html=True)

# CloudTrail Logs tab
with tabs[1]:
    st.markdown(f'<div class="card"><div class="card-header">{get_text("cloudtrail_logs")}</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info(get_text('scan_start_message'))
    else:
        events = st.session_state.cloudtrail_events
        if events:
            # 데이터프레임으로 변환하여 표시
            df = pd.DataFrame(events)
            st.dataframe(df, use_container_width=True)
            
            # CSV 다운로드
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label=get_text('download_csv'),
                data=csv,
                file_name=f"cloudtrail_logs_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv"
            )
        else:
            st.warning(get_text('no_cloudtrail_events'))
    st.markdown('</div></div>', unsafe_allow_html=True)

# Findings tab
with tabs[2]:
    st.markdown(f'<div class="card"><div class="card-header">{get_text("findings")}</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info(get_text('scan_start_message'))
    else:
        # S3, WAF, GuardDuty 탭 생성
        security_tabs = st.tabs([get_text('s3_security_issues'), get_text('waf_security_issues'), get_text('guardduty_findings')])
        
        # S3 탭
        with security_tabs[0]:
            if hasattr(st.session_state, 's3_issues') and st.session_state.s3_issues:
                issues = st.session_state.s3_issues
                st.write(f"총 {len(issues)}개의 S3 보안 이슈가 발견되었습니다." if get_current_language() == 'ko' else f"Found {len(issues)} S3 security issues.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"] if get_current_language() == 'ko' else ["Show All", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox(get_text('severity') + " 필터" if get_current_language() == 'ko' else get_text('severity') + " Filter", severity_options, key="s3_severity")
                
                if selected_severity not in ["모두 보기", "Show All"]:
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
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('severity')}:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('resource')}:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('description')}:</strong> {issue.get('description', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('finding_time')}:</strong> {issue.get('created_at', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(get_text('no_severity_issues_s3').format(severity=selected_severity))
            else:
                st.info(get_text('no_s3_issues'))
        
        # WAF 탭
        with security_tabs[1]:
            if hasattr(st.session_state, 'waf_issues') and st.session_state.waf_issues:
                issues = st.session_state.waf_issues
                st.write(f"총 {len(issues)}개의 WAF 보안 이슈가 발견되었습니다." if get_current_language() == 'ko' else f"Found {len(issues)} WAF security issues.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "HIGH", "MEDIUM", "LOW"] if get_current_language() == 'ko' else ["Show All", "HIGH", "MEDIUM", "LOW"]
                selected_severity = st.selectbox(get_text('severity') + " 필터" if get_current_language() == 'ko' else get_text('severity') + " Filter", severity_options, key="waf_severity")
                
                if selected_severity not in ["모두 보기", "Show All"]:
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
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('severity')}:</strong> {issue.get('severity', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('resource')}:</strong> {issue.get('resource_type', 'N/A')} - {issue.get('resource_id', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('description')}:</strong> {issue.get('description', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(get_text('no_severity_issues_waf').format(severity=selected_severity))
            else:
                st.info(get_text('no_waf_issues'))
        
        # GuardDuty 탭
        with security_tabs[2]:
            # GuardDuty 상태 표시
            status = st.session_state.guardduty_status if hasattr(st.session_state, 'guardduty_status') else {'status': 'UNKNOWN', 'message': get_text('guardduty_unknown')}
            
            status_class = "status-active" if status['status'] == 'ACTIVE' else \
                          "status-warning" if status['status'] == 'PARTIALLY_ACTIVE' else \
                          "status-error" if status['status'] in ['DISABLED', 'NOT_CONFIGURED'] else "status-warning"
            
            status_text = get_text('guardduty_enabled') if status['status'] == 'ACTIVE' else \
                         get_text('guardduty_disabled') if status['status'] in ['DISABLED', 'NOT_CONFIGURED'] else \
                         get_text('guardduty_unknown')
            
            st.markdown(f"""
            <div class="status-indicator {status_class}" style="color: #000000;">
                <strong style="color: #000000;">{get_text('guardduty_status')}:</strong> {status['status']} - {status_text}
            </div>
            """, unsafe_allow_html=True)
            
            if hasattr(st.session_state, 'guardduty_findings') and st.session_state.guardduty_findings:
                findings = st.session_state.guardduty_findings
                st.write(f"총 {len(findings)}개의 GuardDuty 위협이 발견되었습니다." if get_current_language() == 'ko' else f"Found {len(findings)} GuardDuty threats.")
                
                # 심각도별 필터링
                severity_options = ["모두 보기", "높음 (7-10)", "중간 (4-7)", "낮음 (0-4)"] if get_current_language() == 'ko' else ["Show All", "High (7-10)", "Medium (4-7)", "Low (0-4)"]
                selected_severity = st.selectbox(get_text('severity') + " 필터" if get_current_language() == 'ko' else get_text('severity') + " Filter", severity_options, key="gd_severity")
                
                if "높음" in selected_severity or "High" in selected_severity:
                    filtered_findings = [f for f in findings if f.get('심각도', 0) > 7]
                elif "중간" in selected_severity or "Medium" in selected_severity:
                    filtered_findings = [f for f in findings if 4 < f.get('심각도', 0) <= 7]
                elif "낮음" in selected_severity or "Low" in selected_severity:
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
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('severity')}:</strong> {finding.get('심각도', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('issue_type')}:</strong> {finding.get('유형', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('resource')}:</strong> {finding.get('리소스 유형', 'N/A')} - {finding.get('리소스 ID', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('description')}:</strong> {finding.get('설명', 'N/A')}</p>
                            <p style="color: #000000;"><strong style="color: #000000;">{get_text('finding_time')}:</strong> {finding.get('발견 시간', 'N/A')}</p>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.info(get_text('no_severity_issues_guardduty').format(severity=selected_severity))
            else:
                if status['status'] in ['ACTIVE', 'PARTIALLY_ACTIVE']:
                    st.info(get_text('no_guardduty_findings'))
                else:
                    st.warning("GuardDuty가 활성화되지 않았거나 구성되지 않았습니다. AWS 콘솔에서 GuardDuty를 활성화하세요." if get_current_language() == 'ko' else "GuardDuty is not enabled or configured. Please enable GuardDuty in the AWS console.")
                    
                    # GuardDuty 활성화 방법 안내
                    with st.expander("GuardDuty 활성화 방법" if get_current_language() == 'ko' else "How to enable GuardDuty"):
                        if get_current_language() == 'ko':
                            st.markdown("""
                            1. AWS 콘솔에 로그인합니다.
                            2. GuardDuty 서비스로 이동합니다.
                            3. '시작하기' 또는 'GuardDuty 활성화' 버튼을 클릭합니다.
                            4. 설정을 검토하고 '활성화'를 클릭합니다.
                            
                            GuardDuty는 30일 무료 평가판을 제공하며, 이후에는 사용량에 따라 요금이 부과됩니다.
                            """)
                        else:
                            st.markdown("""
                            1. Log in to the AWS console.
                            2. Navigate to the GuardDuty service.
                            3. Click 'Get Started' or 'Enable GuardDuty' button.
                            4. Review the settings and click 'Enable'.
                            
                            GuardDuty offers a 30-day free trial, after which charges apply based on usage.
                            """)
    st.markdown('</div></div>', unsafe_allow_html=True)

# Recommendations tab
with tabs[3]:
    st.markdown(f'<div class="card"><div class="card-header">{get_text("recommendations")}</div><div class="card-content">', unsafe_allow_html=True)
    if not st.session_state.scan_completed:
        st.info(get_text('scan_start_message'))
    else:
        # HIGH 심각도 이슈 필터링
        high_severity_issues = []
        
        # S3 HIGH 이슈
        for issue in st.session_state.s3_issues:
            if issue.get('severity') == 'HIGH':
                high_severity_issues.append({
                    'type': 'S3',
                    'details': issue.get('description', ''),
                    'resource': f"{issue.get('resource_type', '')} - {issue.get('resource_id', '')}"
                })
        
        # WAF HIGH 이슈
        for issue in st.session_state.waf_issues:
            if issue.get('severity') == 'HIGH':
                high_severity_issues.append({
                    'type': 'WAF',
                    'details': issue.get('description', ''),
                    'resource': f"{issue.get('resource_type', '')} - {issue.get('resource_id', '')}"
                })
        
        if high_severity_issues:
            st.warning(f"발견된 HIGH 심각도 이슈: {len(high_severity_issues)}개" if get_current_language() == 'ko' else f"Found HIGH severity issues: {len(high_severity_issues)}")
            
            for idx, issue in enumerate(high_severity_issues):
                with st.expander(f"{issue['type']} - {issue['details']}"):
                    st.markdown(f"**{get_text('resource')}**: {issue['resource']}")
                    
                    button_text = f"Amazon Q에게 {issue['type']} 이슈 해결 방법 물어보기" if get_current_language() == 'ko' else f"Ask Amazon Q for {issue['type']} issue resolution"
                    if st.button(button_text, key=f"q_btn_{issue['type']}_{idx}"):
                        prompt = get_q_recommendation(issue['type'], issue['details'], issue['resource'])
                        st.markdown(f"### {get_text('prompt_for_amazon_q')}")
                        st.code(prompt, language="text")
                        st.info(get_text('copy_prompt_instruction'))
        else:
            st.success(get_text('no_high_severity_issues'))
    st.markdown('</div></div>', unsafe_allow_html=True)

# Footer
footer_text = "AWS 운영자를 위한 보안 대시보드 | Amazon Q 핸즈온 워크샵" if get_current_language() == 'ko' else "Security Dashboard for AWS Operators | Amazon Q Hands-on Workshop"
st.markdown(f'<p style="text-align: center; color: #666666; font-size: 0.8rem; margin-top: 30px;">{footer_text}</p>', unsafe_allow_html=True)
