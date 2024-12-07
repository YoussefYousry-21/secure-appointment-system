import asyncio
from aiosmtpd.controller import Controller
from email.parser import Parser
from email.policy import default

class DebugHandler:
    async def handle_DATA(self, server, session, envelope):
        print('\n=== New Email ===')
        email_parser = Parser(policy=default)
        email_message = email_parser.parsestr(envelope.content.decode('utf8'))
        
        print(f'From: {envelope.mail_from}')
        print(f'To: {envelope.rcpt_tos}')
        print(f'Subject: {email_message["subject"]}')
        print('\nBody:')
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    print(part.get_content())
        else:
            print(email_message.get_content())
        
        print('================\n')
        return '250 Message accepted for delivery'

if __name__ == '__main__':
    handler = DebugHandler()
    controller = Controller(handler, hostname='127.0.0.1', port=2525)
    
    print('Starting SMTP debugging server on localhost:2525')
    try:
        controller.start()
        while True:
            asyncio.get_event_loop().run_until_complete(asyncio.sleep(1))
    except KeyboardInterrupt:
        controller.stop()
        print('\nSMTP debugging server stopped')
