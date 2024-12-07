from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from datetime import datetime
import json
import os
from dotenv import load_dotenv

load_dotenv()

SCOPES = ['https://www.googleapis.com/auth/calendar']

def create_google_auth_flow():
    client_config = {
        "web": {
            "client_id": os.getenv('GOOGLE_CLIENT_ID'),
            "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost:5000/google-auth-callback"]
        }
    }
    
    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/google-auth-callback"
    )
    return flow

def get_google_calendar_service(credentials_json):
    if not credentials_json:
        return None
    
    credentials_dict = json.loads(credentials_json)
    credentials = Credentials.from_authorized_user_info(credentials_dict, SCOPES)
    
    if not credentials or not credentials.valid:
        if credentials and credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
        else:
            return None
    
    return build('calendar', 'v3', credentials=credentials)

def create_google_calendar_event(service, appointment):
    event = {
        'summary': appointment.title,
        'description': appointment.description,
        'start': {
            'dateTime': appointment.start_time.isoformat(),
            'timeZone': 'UTC',
        },
        'end': {
            'dateTime': appointment.end_time.isoformat(),
            'timeZone': 'UTC',
        },
        'reminders': {
            'useDefault': True
        }
    }
    
    event = service.events().insert(calendarId='primary', body=event).execute()
    return event['id']

def update_google_calendar_event(service, appointment):
    event = {
        'summary': appointment.title,
        'description': appointment.description,
        'start': {
            'dateTime': appointment.start_time.isoformat(),
            'timeZone': 'UTC',
        },
        'end': {
            'dateTime': appointment.end_time.isoformat(),
            'timeZone': 'UTC',
        }
    }
    
    service.events().update(
        calendarId='primary',
        eventId=appointment.google_calendar_event_id,
        body=event
    ).execute()

def delete_google_calendar_event(service, event_id):
    service.events().delete(calendarId='primary', eventId=event_id).execute()
