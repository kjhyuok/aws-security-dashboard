import streamlit as st
import os
import boto3
from dotenv import load_dotenv
import amazon_q_page

# 환경 변수 로드
load_dotenv()

# 세션 상태 초기화
if 'security_simulator_lambda' not in st.session_state:
    st.session_state.security_simulator_lambda = os.getenv('SECURITY_SIMULATOR_LAMBDA', '')

# 페이지 설정
st.set_page_config(
    page_title="AWS 보안 대시보드",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 사이드바
st.sidebar.title("AWS 보안 대시보드")
st.sidebar.markdown("---")

# 페이지 선택
page = st.sidebar.selectbox(
    "페이지 선택",
    ["대시보드", "CloudTrail 로그", "GuardDuty 탐지", "VPC Flow 로그", "WAF 로그", "Amazon Q 보안 조치"]
)

# 환경 정보 표시
st.sidebar.markdown("---")
st.sidebar.subheader("환경 정보")
st.sidebar.markdown(f"""
- **계정 ID:** {os.getenv('ACCOUNT_ID', 'N/A')}
- **리전:** {os.getenv('REGION', 'N/A')}
- **환경:** {os.getenv('ENVIRONMENT', 'N/A')}
""")

# 페이지 내용
if page == "대시보드":
    st.title("AWS 보안 대시보드")
    st.markdown("""
    ## 보안 서비스 현황
    
    이 대시보드에서는 다양한 AWS 보안 서비스의 현황을 확인할 수 있습니다.
    """)
    
    # 보안 서비스 상태 표시
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(label="GuardDuty 탐지", value="활성화됨")
    
    with col2:
        st.metric(label="CloudTrail", value="활성화됨")
    
    with col3:
        st.metric(label="VPC Flow Logs", value="활성화됨")
    
    # 추가 정보
    st.markdown("---")
    st.subheader("보안 서비스 설정")
    st.markdown("""
    다음 보안 서비스가 구성되어 있습니다:
    
    - **CloudTrail**: 모든 API 활동 로깅
    - **GuardDuty**: 위협 탐지 활성화
    - **VPC Flow Logs**: 네트워크 트래픽 모니터링
    - **WAF**: 웹 애플리케이션 방화벽
    - **Route53 DNS 쿼리 로깅**: DNS 쿼리 모니터링
    
    왼쪽 사이드바에서 각 서비스의 상세 정보를 확인할 수 있습니다.
    """)

elif page == "CloudTrail 로그":
    st.title("CloudTrail 로그")
    st.markdown("""
    ## CloudTrail 이벤트 로그
    
    최근 CloudTrail 이벤트를 확인할 수 있습니다.
    """)
    
    # 여기에 CloudTrail 로그 조회 및 표시 코드 추가

elif page == "GuardDuty 탐지":
    st.title("GuardDuty 탐지 결과")
    st.markdown("""
    ## GuardDuty 탐지 결과
    
    GuardDuty에서 탐지한 보안 위협을 확인할 수 있습니다.
    """)
    
    # 여기에 GuardDuty 탐지 결과 조회 및 표시 코드 추가

elif page == "VPC Flow 로그":
    st.title("VPC Flow 로그")
    st.markdown("""
    ## VPC Flow 로그
    
    VPC 네트워크 트래픽 로그를 확인할 수 있습니다.
    """)
    
    # 여기에 VPC Flow 로그 조회 및 표시 코드 추가

elif page == "WAF 로그":
    st.title("WAF 로그")
    st.markdown("""
    ## WAF 로그
    
    WAF에서 차단한 요청을 확인할 수 있습니다.
    """)
    
    # 여기에 WAF 로그 조회 및 표시 코드 추가

elif page == "Amazon Q 보안 조치":
    # Amazon Q 페이지 표시
    amazon_q_page.show_amazon_q_page()
