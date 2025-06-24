"""
다국어 지원 유틸리티
"""

import streamlit as st
from datetime import datetime
from .translations import TRANSLATIONS

def init_language():
    """언어 설정 초기화"""
    if 'language' not in st.session_state:
        st.session_state.language = 'ko'

def get_text(key, lang=None):
    """번역된 텍스트 반환"""
    if lang is None:
        lang = st.session_state.get('language', 'ko')
    
    return TRANSLATIONS.get(lang, {}).get(key, key)

def set_language(lang):
    """언어 설정"""
    st.session_state.language = lang

def get_current_language():
    """현재 언어 반환"""
    return st.session_state.get('language', 'ko')

def language_selector():
    """언어 선택 UI 컴포넌트"""
    current_lang = get_current_language()
    lang_options = {'한국어': 'ko', 'English': 'en'}
    
    # 현재 언어에 따른 기본 선택값 설정
    current_display = '한국어' if current_lang == 'ko' else 'English'
    
    selected = st.selectbox(
        get_text('language'),
        options=list(lang_options.keys()),
        index=list(lang_options.keys()).index(current_display),
        key='language_selector'
    )
    
    # 언어가 변경되었을 때만 업데이트
    if lang_options[selected] != current_lang:
        set_language(lang_options[selected])
        st.rerun()

def format_datetime(dt, lang=None):
    """언어에 따른 날짜 형식 반환"""
    if lang is None:
        lang = get_current_language()
    
    if lang == 'ko':
        return dt.strftime(f"%Y{get_text('year')} %m{get_text('month')} %d{get_text('day')} %H:%M")
    else:
        return dt.strftime("%Y-%m-%d %H:%M")

def format_date(dt, lang=None):
    """언어에 따른 날짜만 형식 반환"""
    if lang is None:
        lang = get_current_language()
    
    if lang == 'ko':
        return dt.strftime("%Y-%m-%d")
    else:
        return dt.strftime("%Y-%m-%d")

def get_count_text(count, item_type):
    """언어에 따른 개수 표시 텍스트 반환"""
    lang = get_current_language()
    
    if lang == 'ko':
        if item_type in ['users', 'users_without_mfa']:
            return f"{count}{get_text('people_suffix')}"
        else:
            return f"{count}{get_text('count_suffix')}"
    else:
        return f"{count} {get_text(f'{item_type}_count')}"

def get_tab_emoji():
    """언어에 따른 탭 이모지 반환 (선택사항)"""
    return {
        'iam': '👥',
        'cloudtrail': '📜',
        'findings': '⚠️',
        'recommendations': '📝'
    }
