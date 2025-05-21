import streamlit as st
import pandas as pd
from datetime import datetime
from utils.aws_client import create_aws_session, get_iam_info, get_cloudtrail_events

# Page configuration
st.set_page_config(page_title="AWS Security Dashboard", page_icon="🔒", layout="wide")

# Load CSS
with open('styles/main.css') as f:
    st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Initialize session state variables
if 'scan_completed' not in st.session_state:
    st.session_state.scan_completed = False

# Sidebar
with st.sidebar:
    st.markdown("<h1 style='margin-top:0; font-size:1.5rem; color:#FF9900;'>AWS Security Dashboard</h1>", unsafe_allow_html=True)
    
    # Account information
    st.markdown("<p class='account-info-text'>계정 정보</p>", unsafe_allow_html=True)
    account_id = st.text_input("AWS 계정 ID", placeholder="123456789012")
    use_profile = st.checkbox("AWS CLI 프로필 사용", value=False)
    
    # Initialize variables
    profile_name = "default"
    access_key = ""
    secret_key = ""
    
    if use_profile:
        profile_name = st.text_input("AWS 프로필 이름", value="default")
        aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"])
    else:
        access_key = st.text_input("AWS Access Key ID", type="password")
        secret_key = st.text_input("AWS Secret Access Key", type="password")
        aws_region = st.selectbox("AWS 리전", ["ap-northeast-2", "us-east-1", "us-west-2"])
    
    scan_button = st.button("보안 스캔 시작")

# Main content
st.markdown('<h1 class="dashboard-title">AWS Security Dashboard</h1>', unsafe_allow_html=True)
st.markdown(f'<p class="last-scan">마지막 스캔: {datetime.now().strftime("%Y년 %m월 %d일 %H:%M")}</p>', unsafe_allow_html=True)

# Tabs
tabs = st.tabs(["👥 IAM 계정 현황", "📜 CloudTrail 로그", "⚠️ 발견 사항", "📝 권장 조치"])

# Scan button handler
if scan_button:
    if not account_id:
        st.sidebar.error("AWS 계정 ID를 입력해주세요.")
    elif use_profile and not profile_name:
        st.sidebar.error("AWS 프로필 이름을 입력해주세요.")
    elif not use_profile and (not access_key or not secret_key):
        st.sidebar.error("AWS Access Key와 Secret Key를 모두 입력해주세요.")
    else:
        try:
            with st.spinner("AWS 계정 정보를 가져오는 중입니다..."):
                # Create AWS session
                session = create_aws_session(use_profile, profile_name, access_key, secret_key, aws_region)
                
                # Get IAM information
                iam_info = get_iam_info(session)
                st.session_state.iam_info = iam_info
                
                # Get CloudTrail events
                cloudtrail_events = get_cloudtrail_events(session)
                st.session_state.cloudtrail_events = cloudtrail_events
                
                # Set scan completed flag
                st.session_state.scan_completed = True
                
                # Show success message
                st.sidebar.success(f"AWS 계정 정보를 성공적으로 가져왔습니다.")
                st.sidebar.info(f"사용자: {len(iam_info['users'])}명, 역할: {len(iam_info['roles'])}개, 그룹: {len(iam_info['groups'])}개")
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
    st.info("발견 사항 기능은 현재 개발 중입니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Recommendations tab
with tabs[3]:
    st.markdown('<div class="card"><div class="card-header">권장 조치</div><div class="card-content">', unsafe_allow_html=True)
    st.info("권장 조치 기능은 현재 개발 중입니다.")
    st.markdown('</div></div>', unsafe_allow_html=True)

# Footer
st.markdown('<p style="text-align: center; color: #666666; font-size: 0.8rem; margin-top: 30px;">AWS 운영자를 위한 보안 대시보드 | Amazon Q 핸즈온 워크샵</p>', unsafe_allow_html=True)

