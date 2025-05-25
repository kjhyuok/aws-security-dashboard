import streamlit as st
import boto3
import json
import pandas as pd
from datetime import datetime
from amazon_q_helper import get_security_events, get_amazon_q_recommendation

def show_amazon_q_page():
    st.title("Amazon Q 보안 조치 도우미")
    
    st.markdown("""
    ## 보안 이벤트 분석 및 조치
    
    이 페이지에서는 감지된 보안 이벤트를 분석하고 Amazon Q에게 조치 방법을 물어볼 수 있습니다.
    """)
    
    # 보안 이벤트 가져오기
    if st.button("보안 이벤트 새로고침"):
        st.session_state.security_events = get_security_events()
    
    if 'security_events' not in st.session_state:
        st.session_state.security_events = get_security_events()
    
    events = st.session_state.security_events
    
    if not events:
        st.info("감지된 보안 이벤트가 없습니다.")
        
        # 시뮬레이션 버튼 추가
        if st.button("보안 위협 시뮬레이션 실행"):
            st.warning("보안 위협 시뮬레이션을 실행 중입니다. 잠시 후 결과를 확인하세요.")
            try:
                lambda_client = boto3.client('lambda')
                lambda_client.invoke(
                    FunctionName=st.session_state.get('security_simulator_lambda', ''),
                    InvocationType='Event'
                )
                st.success("시뮬레이션이 시작되었습니다. 1-2분 후에 새로고침 버튼을 클릭하세요.")
            except Exception as e:
                st.error(f"시뮬레이션 실행 중 오류가 발생했습니다: {str(e)}")
    else:
        # 이벤트 목록 표시
        st.subheader("감지된 보안 이벤트")
        
        # 표시할 데이터 준비
        display_data = []
        for e in events:
            display_data.append({
                'ID': e.get('id', 'N/A')[:8] + '...',
                '유형': e.get('type', 'N/A'),
                '심각도': e.get('severity', 'N/A'),
                '제목': e.get('title', 'N/A'),
                '시간': e.get('time', 'N/A')
            })
        
        df = pd.DataFrame(display_data)
        st.dataframe(df)
        
        # 선택한 이벤트에 대한 상세 정보 및 Amazon Q 조치 방법
        event_ids = [e['id'] for e in events]
        selected_event_id = st.selectbox("분석할 이벤트 선택", event_ids)
        
        if selected_event_id:
            selected_event = next((e for e in events if e['id'] == selected_event_id), None)
            
            if selected_event:
                st.subheader("이벤트 상세 정보")
                
                # 주요 정보 표시
                st.markdown(f"""
                **유형:** {selected_event.get('type', 'N/A')}  
                **심각도:** {selected_event.get('severity', 'N/A')}  
                **제목:** {selected_event.get('title', 'N/A')}  
                **설명:** {selected_event.get('description', 'N/A')}  
                **시간:** {selected_event.get('time', 'N/A')}  
                """)
                
                # 원시 데이터 표시 (접을 수 있는 섹션)
                with st.expander("원시 데이터 보기"):
                    st.json(selected_event.get('raw', {}))
                
                st.subheader("Amazon Q 조치 방법")
                recommendation = get_amazon_q_recommendation(selected_event)
                st.markdown(recommendation['recommendation'])
                
                # 조치 상태 업데이트
                status_options = ["NEW", "INVESTIGATING", "MITIGATED", "RESOLVED", "FALSE_POSITIVE"]
                new_status = st.selectbox("이벤트 상태 업데이트", status_options, index=0)
                
                if st.button("상태 업데이트"):
                    st.success(f"이벤트 상태가 {new_status}로 업데이트되었습니다.")
                    
                # Amazon Q에게 물어보기 섹션
                st.subheader("Amazon Q에게 물어보기")
                st.markdown("""
                Amazon Q Developer에게 이 보안 이벤트에 대해 물어보세요. 예시 질문:
                - 이 GuardDuty 탐지 결과를 어떻게 해결해야 하나요?
                - 이 WAF 차단 이벤트를 어떻게 분석해야 하나요?
                - 이 보안 그룹 설정의 문제점은 무엇인가요?
                """)
                
                query = st.text_area("Amazon Q에게 질문하기", height=100)
                if st.button("Amazon Q에게 물어보기"):
                    if query:
                        st.info("Amazon Q Developer를 사용하려면 AWS 콘솔에서 Amazon Q Developer를 활성화하고 사용하세요.")
                        st.markdown("""
                        **참고:** 이 데모 애플리케이션에서는 실제 Amazon Q API를 호출하지 않습니다. 
                        실제 환경에서는 AWS 콘솔의 Amazon Q Developer를 사용하여 질문하세요.
                        """)
